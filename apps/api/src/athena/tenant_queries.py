from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from athena.models import TenantScopedMixin
from athena.tenancy import TenantIsolationError


def apply_tenant_scope(
    session: Session,
    statement: Select[Any],
    model: type[TenantScopedMixin],
) -> Select[Any]:
    """Apply mandatory tenant authority to a tenant-scoped statement."""
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        raise TenantIsolationError("A validated tenant context is required for scoped queries")
    return statement.where(model.tenant_id == tenant_id)


def tenant_select[TenantModel: TenantScopedMixin](
    session: Session,
    model: type[TenantModel],
    *criteria: ColumnElement[bool],
) -> Select[tuple[TenantModel]]:
    """Build a select that fails closed unless validated tenant authority is present."""
    return apply_tenant_scope(session, select(model).where(*criteria), model)
