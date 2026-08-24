from datetime import UTC, datetime, timedelta

import pytest
from athena.models import Base, Tenant
from athena.services.request_controls import RequestControlError, RequestControls
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _session() -> tuple[object, Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine, info={"tenant_id": "tenant-a"})
    session.add(
        Tenant(
            id="tenant-a",
            display_name="Tenant A",
            approval_reference="test",
            authorized_by="test",
            approved_at=datetime(2026, 8, 24, tzinfo=UTC),
            inventory_sha256="0" * 64,
        )
    )
    session.commit()
    return engine, session


def test_replay_reservation_is_idempotent_and_payload_bound() -> None:
    engine, session = _session()
    controls = RequestControls(session)
    first = controls.reserve(
        namespace="webhook",
        idempotency_key="delivery-1",
        request_bytes=b"one",
        ttl=timedelta(minutes=5),
    )
    second = controls.reserve(
        namespace="webhook",
        idempotency_key="delivery-1",
        request_bytes=b"one",
        ttl=timedelta(minutes=5),
    )
    assert first.replayed is False
    assert second == type(second)(True, first.reservation_id)
    with pytest.raises(RequestControlError, match="different request"):
        controls.reserve(
            namespace="webhook",
            idempotency_key="delivery-1",
            request_bytes=b"two",
            ttl=timedelta(minutes=5),
        )
    session.close()
    engine.dispose()


def test_rate_limit_is_shared_through_persistent_bucket() -> None:
    engine, session = _session()
    now = datetime(2026, 8, 24, 21, 0, 30, tzinfo=UTC)
    controls = RequestControls(session, clock=lambda: now)
    assert controls.admit(
        namespace="telemetry", subject="alice", limit=2, window=timedelta(minutes=1)
    ).allowed
    assert controls.admit(
        namespace="telemetry", subject="alice", limit=2, window=timedelta(minutes=1)
    ).allowed
    denied = controls.admit(
        namespace="telemetry", subject="alice", limit=2, window=timedelta(minutes=1)
    )
    assert denied.allowed is False
    assert denied.retry_after_seconds == 30
    session.close()
    engine.dispose()
