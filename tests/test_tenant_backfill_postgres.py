import os
from datetime import UTC, datetime

import pytest
from athena.models import AuditEvent, Base, Tenant
from athena.services.tenant_backfill import (
    build_bootstrap_backfill_plan,
    execute_bootstrap_backfill,
)
from athena.services.tenant_inventory import capture_tenant_inventory
from athena.tenant_transition import BootstrapTenantApproval, tenant_inventory_digest
from sqlalchemy import create_engine, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker


@pytest.mark.skipif(
    not os.getenv("ATHENA_TEST_DATABASE_URL"),
    reason="ATHENA_TEST_DATABASE_URL is required for the disposable PostgreSQL test",
)
def test_transactional_backfill_preserves_and_restores_immutable_controls() -> None:
    engine = create_engine(os.environ["ATHENA_TEST_DATABASE_URL"])
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory.begin() as session:
        session.add(
            AuditEvent(
                actor_type="test",
                actor_id="operator",
                action="seed",
                entity_type="test",
                entity_id="evidence-1",
            )
        )
    with factory() as session:
        counts = capture_tenant_inventory(session).table_counts
    approval = BootstrapTenantApproval(
        tenant_id="athena-test",
        display_name="Athena disposable test",
        approval_reference="DISPOSABLE-TEST-2026-001",
        authorized_by="test-suite",
        approved_at=datetime(2026, 8, 21, 4, 0, tzinfo=UTC),
        expected_preexisting_rows=counts,
        inventory_sha256=tenant_inventory_digest(counts),
    )
    with factory.begin() as session:
        plan = build_bootstrap_backfill_plan(session, approval)
        result = execute_bootstrap_backfill(
            session,
            approval,
            confirmed_plan_sha256=plan.plan_sha256,
        )

    assert result.assigned_rows == 1
    assert result.assigned_table_counts["audit_events"] == 1
    with factory() as session:
        event = session.scalar(select(AuditEvent))
        assert event is not None and event.tenant_id == "athena-test"
        assert session.get(Tenant, "athena-test") is not None
        with pytest.raises(DBAPIError, match="append-only"):
            session.execute(update(Base.metadata.tables["audit_events"]).values(action="changed"))
        session.rollback()
    engine.dispose()
