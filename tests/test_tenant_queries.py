import pytest
from athena.models import Identity
from athena.tenancy import TenantIsolationError
from athena.tenant_queries import apply_tenant_scope, tenant_select
from sqlalchemy import func, select
from sqlalchemy.orm import Session


def test_tenant_queries_reject_missing_tenant_authority() -> None:
    session = Session(info={"tenant_id": None})

    with pytest.raises(TenantIsolationError, match="tenant context is required"):
        tenant_select(session, Identity)
    with pytest.raises(TenantIsolationError, match="tenant context is required"):
        apply_tenant_scope(session, select(func.count()).select_from(Identity), Identity)


def test_tenant_queries_reject_administrative_migration_sessions() -> None:
    session = Session(info={"administrative_scope": "migration"})

    with pytest.raises(TenantIsolationError, match="tenant context is required"):
        tenant_select(session, Identity)
