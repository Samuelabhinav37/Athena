from datetime import UTC, datetime

import pytest
from athena.models import Base, Identity, IdentityType, Tenant
from athena.services.tenant_backfill import (
    build_bootstrap_backfill_plan,
    execute_bootstrap_backfill,
)
from athena.tenant_transition import (
    TENANT_TABLES,
    BootstrapTenantApproval,
    TenantTransitionError,
    tenant_inventory_digest,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _approval(counts: dict[str, int]) -> BootstrapTenantApproval:
    return BootstrapTenantApproval(
        tenant_id="athena-local",
        display_name="Athena Local Development",
        approval_reference="LOCAL-BOOTSTRAP-2026-001",
        authorized_by="samue",
        approved_at=datetime(2026, 8, 21, 2, 49, tzinfo=UTC),
        expected_preexisting_rows=counts,
        inventory_sha256=tenant_inventory_digest(counts),
    )


def _database():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_backfill_plan_is_deterministic_and_never_writes() -> None:
    engine, factory = _database()
    counts = {table: 0 for table in TENANT_TABLES}
    with factory() as session:
        first = build_bootstrap_backfill_plan(session, _approval(counts))
        second = build_bootstrap_backfill_plan(session, _approval(counts))

        assert first == second
        assert first.status == "dry_run"
        assert first.database_mutation is False
        assert first.total_rows == 0
        assert session.get(Tenant, "athena-local") is None
        assert not session.new and not session.dirty and not session.deleted
    engine.dispose()


def test_backfill_plan_fails_closed_on_changed_inventory() -> None:
    engine, factory = _database()
    counts = {table: 0 for table in TENANT_TABLES}
    with factory.begin() as session:
        session.add(
            Identity(
                source="keycloak",
                external_id="alice",
                username="alice",
                identity_type=IdentityType.HUMAN,
                display_name="Alice",
                active=True,
            )
        )
    with factory() as session, pytest.raises(TenantTransitionError, match="differs"):
        build_bootstrap_backfill_plan(session, _approval(counts))
    engine.dispose()


def test_backfill_plan_rejects_existing_tenant_or_assigned_rows() -> None:
    engine, factory = _database()
    counts = {table: 0 for table in TENANT_TABLES}
    with factory.begin() as session:
        session.add(
            Tenant(
                id="athena-local",
                display_name="Existing",
                approval_reference="LOCAL-BOOTSTRAP-2026-001",
                authorized_by="samue",
                approved_at=datetime(2026, 8, 21, 2, 49, tzinfo=UTC),
                inventory_sha256=tenant_inventory_digest(counts),
            )
        )
    with factory() as session, pytest.raises(TenantTransitionError, match="already exists"):
        build_bootstrap_backfill_plan(session, _approval(counts))
    engine.dispose()


def test_backfill_plan_rejects_preassigned_rows() -> None:
    engine, factory = _database()
    empty_counts = {table: 0 for table in TENANT_TABLES}
    counts = dict(empty_counts)
    counts["identities"] = 1
    with factory.begin() as session:
        session.add(
            Tenant(
                id="other-tenant",
                display_name="Other tenant",
                approval_reference="OTHER-TENANT-2026-001",
                authorized_by="operator",
                approved_at=datetime(2026, 8, 21, 2, 49, tzinfo=UTC),
                inventory_sha256=tenant_inventory_digest(empty_counts),
            )
        )
        session.add(
            Identity(
                source="keycloak",
                external_id="alice",
                username="alice",
                identity_type=IdentityType.HUMAN,
                display_name="Alice",
                active=True,
                tenant_id="other-tenant",
            )
        )
    with factory() as session, pytest.raises(TenantTransitionError, match="unassigned"):
        build_bootstrap_backfill_plan(session, _approval(counts))
    engine.dispose()


def test_executable_backfill_rejects_non_postgresql_without_writing() -> None:
    engine, factory = _database()
    counts = {table: 0 for table in TENANT_TABLES}
    with factory.begin() as session, pytest.raises(
        TenantTransitionError, match="requires PostgreSQL"
    ):
        execute_bootstrap_backfill(
            session,
            _approval(counts),
            confirmed_plan_sha256="a" * 64,
        )
    with factory() as session:
        assert session.get(Tenant, "athena-local") is None
    engine.dispose()
