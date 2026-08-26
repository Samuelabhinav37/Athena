from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint, and_, func, select
from sqlalchemy.orm import Session

from athena.models import Base
from athena.tenant_transition import TENANT_TABLES


class TenantIntegrityError(RuntimeError):
    pass


CROSS_TENANT_AUTHORITY_CONSTRAINTS = frozenset(
    {"connector_scope_bindings.uq_connector_scope_bindings_connector_scope"}
)


class TenantRelationshipCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    relationship: str
    mismatched_rows: int


class TenantIntegrityReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    database_mutation: Literal[False] = False
    ready_for_tenant_constraints: bool
    unassigned_rows: dict[str, int]
    relationship_checks: tuple[TenantRelationshipCheck, ...]
    global_unique_constraints: tuple[str, ...]


def inspect_tenant_integrity(session: Session) -> TenantIntegrityReport:
    if session.new or session.dirty or session.deleted:
        raise TenantIntegrityError("Tenant integrity inspection requires no pending changes")

    unassigned: dict[str, int] = {}
    relationship_checks: list[TenantRelationshipCheck] = []
    unique_constraints: list[str] = []
    with session.no_autoflush:
        for table_name in TENANT_TABLES:
            table = Base.metadata.tables[table_name]
            count = int(
                session.scalar(
                    select(func.count()).select_from(table).where(table.c.tenant_id.is_(None))
                )
                or 0
            )
            if count:
                unassigned[table_name] = count

            for constraint in table.constraints:
                is_global = (
                    isinstance(constraint, UniqueConstraint)
                    and "tenant_id" not in constraint.columns
                )
                if is_global:
                    reference = f"{table_name}.{constraint.name}"
                    if reference not in CROSS_TENANT_AUTHORITY_CONSTRAINTS:
                        unique_constraints.append(reference)

            for foreign_key in table.foreign_key_constraints:
                if not isinstance(foreign_key, ForeignKeyConstraint):
                    continue
                elements = tuple(foreign_key.elements)
                parent = elements[0].column.table
                if parent.name not in TENANT_TABLES:
                    continue
                business_elements = tuple(
                    element for element in elements if element.parent.name != "tenant_id"
                )
                mismatch = int(
                    session.scalar(
                        select(func.count())
                        .select_from(
                            table.join(
                                parent,
                                and_(
                                    *(
                                        element.parent == element.column
                                        for element in business_elements
                                    )
                                ),
                            )
                        )
                        .where(table.c.tenant_id.is_distinct_from(parent.c.tenant_id))
                    )
                    or 0
                )
                child_columns = ",".join(
                    element.parent.name for element in business_elements
                )
                parent_columns = ",".join(
                    element.column.name for element in business_elements
                )
                relationship_checks.append(
                    TenantRelationshipCheck(
                        relationship=f"{table_name}.{child_columns}->{parent.name}.{parent_columns}",
                        mismatched_rows=mismatch,
                    )
                )

    relationship_checks.sort(key=lambda check: check.relationship)
    mismatches = sum(check.mismatched_rows for check in relationship_checks)
    return TenantIntegrityReport(
        ready_for_tenant_constraints=not unassigned and not mismatches,
        unassigned_rows=dict(sorted(unassigned.items())),
        relationship_checks=tuple(relationship_checks),
        global_unique_constraints=tuple(sorted(unique_constraints)),
    )
