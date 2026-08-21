from datetime import UTC, datetime

import pytest
from athena.models import Base, Group, Identity, IdentityType, Tenant, identity_groups
from athena.services.tenant_integrity import (
    TenantIntegrityError,
    inspect_tenant_integrity,
)
from sqlalchemy import create_engine, insert
from sqlalchemy.orm import sessionmaker


def _tenant(tenant_id: str) -> Tenant:
    return Tenant(
        id=tenant_id,
        display_name=tenant_id,
        approval_reference=f"TEST-{tenant_id}-2026",
        authorized_by="test-suite",
        approved_at=datetime(2026, 8, 21, 4, 0, tzinfo=UTC),
        inventory_sha256="0" * 64,
    )


def test_integrity_report_finds_unassigned_rows_and_global_uniqueness() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
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
    with factory() as session:
        report = inspect_tenant_integrity(session)
        assert report.database_mutation is False
        assert report.ready_for_tenant_constraints is False
        assert report.unassigned_rows == {"identities": 1}
        assert "identities.uq_identity_source_external" in report.global_unique_constraints
    engine.dispose()


def test_integrity_report_finds_cross_tenant_association() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory.begin() as session:
        session.add_all([_tenant("tenant-a"), _tenant("tenant-b")])
        identity = Identity(
            source="keycloak",
            external_id="alice",
            username="alice",
            identity_type=IdentityType.HUMAN,
            display_name="Alice",
            active=True,
            tenant_id="tenant-a",
        )
        group = Group(
            source="keycloak",
            external_id="engineering",
            name="Engineering",
            path="/engineering",
            tenant_id="tenant-b",
        )
        session.add_all([identity, group])
        session.flush()
        session.execute(
            insert(identity_groups).values(
                tenant_id="tenant-a",
                identity_id=identity.id,
                group_id=group.id,
            )
        )
    with factory() as session:
        report = inspect_tenant_integrity(session)
        mismatches = {
            check.relationship: check.mismatched_rows for check in report.relationship_checks
        }
        assert mismatches["identity_groups.group_id->groups.id"] == 1
        assert report.ready_for_tenant_constraints is False
    engine.dispose()


def test_integrity_inspection_rejects_pending_session_changes() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as session:
        session.add(_tenant("pending"))
        with pytest.raises(TenantIntegrityError, match="no pending changes"):
            inspect_tenant_integrity(session)
    engine.dispose()
