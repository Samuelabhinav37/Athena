from sqlalchemy import Select, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from athena.models import TenantScopedMixin


def tenant_select[TenantModel: TenantScopedMixin](
    session: Session,
    model: type[TenantModel],
    *criteria: ColumnElement[bool],
) -> Select[tuple[TenantModel]]:
    """Build a tenant-scoped select, preserving explicit administrative session access."""
    statement = select(model).where(*criteria)
    tenant_id = session.info.get("tenant_id")
    if tenant_id is not None:
        statement = statement.where(model.tenant_id == tenant_id)
    return statement
