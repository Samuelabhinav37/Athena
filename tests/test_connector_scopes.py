from datetime import UTC, datetime

import pytest
from athena.models import Base, ConnectorScopeBinding, ConnectorScopeRevocation
from athena.services.connector_scopes import ConnectorScopeError, ConnectorScopeRegistry
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def test_connector_scope_registry_accepts_only_current_tenant_binding() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, info={"tenant_id": "tenant-a"}) as session:
        session.add(
            ConnectorScopeBinding(
                tenant_id="tenant-a",
                connector="github",
                scope="example-org",
                approval_reference="change-123",
                approved_by="security@example.com",
                approved_at=datetime(2026, 8, 23, tzinfo=UTC),
            )
        )
        session.commit()

        binding = ConnectorScopeRegistry(session).require_approved("GitHub", "Example-Org")

        assert binding.approval_reference == "change-123"
        with pytest.raises(ConnectorScopeError, match="not approved"):
            ConnectorScopeRegistry(session).require_approved("github", "other-org")


def test_connector_scope_registry_rejects_append_only_revocation() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, info={"tenant_id": "tenant-a"}) as session:
        binding = ConnectorScopeBinding(
            tenant_id="tenant-a",
            connector="azure",
            scope="old-tenant/old-subscription",
            approval_reference="approval-123",
            approved_by="security@example.com",
            approved_at=datetime(2026, 8, 23, tzinfo=UTC),
        )
        session.add(binding)
        session.flush()
        revocation = ConnectorScopeRevocation(
            tenant_id="tenant-a",
            binding_id=binding.id,
            approval_reference="revocation-123",
            revoked_by="security@example.com",
            revoked_at=datetime(2026, 8, 24, tzinfo=UTC),
            reason="Scope replaced",
        )
        session.add(revocation)
        session.commit()

        with pytest.raises(ConnectorScopeError, match="revoked"):
            ConnectorScopeRegistry(session).require_approved(
                "azure", "old-tenant/old-subscription"
            )

        revocation.reason = "tampered"
        with pytest.raises(ValueError, match="immutable"):
            session.commit()
    engine.dispose()
