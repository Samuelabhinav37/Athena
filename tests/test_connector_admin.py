from datetime import UTC, datetime

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, ConnectorScopeBinding, ConnectorScopeRevocation, Tenant
from athena.services.connector_admin import (
    ConnectorAdministration,
    ConnectorAdministrationError,
)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool


def test_connector_administration_requires_exact_plan_digest() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, 21, 0, tzinfo=UTC)
    with Session(engine) as session:
        session.add(
            Tenant(
                id="tenant-a",
                display_name="Tenant A",
                approval_reference="tenant-approval",
                authorized_by="security@example.com",
                approved_at=now,
                inventory_sha256="0" * 64,
            )
        )
        session.commit()
        administration = ConnectorAdministration(session)
        plan = administration.plan_approval(
            tenant_id="tenant-a",
            connector=" GitHub ",
            scope=" Example-Org ",
            approval_reference="change-123",
            authorized_by="security@example.com",
            authorized_at=now,
        )

        with pytest.raises(ConnectorAdministrationError, match="digest"):
            administration.apply(plan, confirmed_plan_sha256="0" * 64)
        administration.apply(plan, confirmed_plan_sha256=plan.plan_sha256)
        session.commit()

        binding = session.scalar(select(ConnectorScopeBinding))
        assert binding is not None
        assert (binding.connector, binding.scope) == ("github", "example-org")
    engine.dispose()


def test_connector_revocation_is_append_only_and_replay_safe() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, 21, 0, tzinfo=UTC)
    with Session(engine) as session:
        session.add_all(
            [
                Tenant(
                    id="tenant-a",
                    display_name="Tenant A",
                    approval_reference="tenant-approval",
                    authorized_by="security@example.com",
                    approved_at=now,
                    inventory_sha256="0" * 64,
                ),
                ConnectorScopeBinding(
                    tenant_id="tenant-a",
                    connector="github",
                    scope="example-org",
                    approval_reference="change-123",
                    approved_by="security@example.com",
                    approved_at=now,
                ),
            ]
        )
        session.commit()
        administration = ConnectorAdministration(session)
        plan = administration.plan_revocation(
            tenant_id="tenant-a",
            connector="github",
            scope="example-org",
            approval_reference="change-456",
            authorized_by="security@example.com",
            authorized_at=now,
            reason="Scope retired",
        )
        administration.apply(plan, confirmed_plan_sha256=plan.plan_sha256)
        session.commit()

        assert session.scalar(select(func.count()).select_from(ConnectorScopeRevocation)) == 1
        with pytest.raises(ConnectorAdministrationError, match="already revoked"):
            administration.apply(plan, confirmed_plan_sha256=plan.plan_sha256)
    engine.dispose()


def test_connector_scope_inventory_reports_revocation_without_sensitive_data() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, 21, 0, tzinfo=UTC)
    with Session(engine, info={"tenant_id": "tenant-a"}) as session:
        binding = ConnectorScopeBinding(
            tenant_id="tenant-a",
            connector="github",
            scope="example-org",
            approval_reference="approval-1",
            approved_by="security@example.com",
            approved_at=now,
        )
        session.add(binding)
        session.flush()
        session.add(
            ConnectorScopeRevocation(
                tenant_id="tenant-a",
                binding_id=binding.id,
                approval_reference="revocation-1",
                revoked_by="security@example.com",
                revoked_at=now,
                reason="Retired",
            )
        )
        session.commit()
        app.dependency_overrides[get_db_session] = lambda: session
        try:
            response = TestClient(app).get("/v1/connectors/scopes")
        finally:
            app.dependency_overrides.clear()
        assert response.status_code == 200
        assert response.json()[0]["active"] is False
        assert response.json()[0]["revocation_reference"] == "revocation-1"
        assert "reason" not in response.json()[0]
    engine.dispose()
