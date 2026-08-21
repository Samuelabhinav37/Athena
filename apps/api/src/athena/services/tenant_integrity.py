from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import UniqueConstraint, func, select
from sqlalchemy.orm import Session

from athena.models import Base
from athena.tenant_transition import TENANT_TABLES


class TenantIntegrityError(RuntimeError):
    pass


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
                    select(func.count())
                    .select_from(table)
                    .where(table.c.tenant_id.is_(None))
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
                    unique_constraints.append(f"{table_name}.{constraint.name}")

            for foreign_key in table.foreign_keys:
                parent = foreign_key.column.table
                if parent.name not in TENANT_TABLES:
                    continue
                mismatch = int(
                    session.scalar(
                        select(func.count())
                        .select_from(table.join(parent, foreign_key.parent == foreign_key.column))
                        .where(table.c.tenant_id.is_distinct_from(parent.c.tenant_id))
                    )
                    or 0
                )
                relationship_checks.append(
                    TenantRelationshipCheck(
                        relationship=(
                            f"{table_name}.{foreign_key.parent.name}->"
                            f"{parent.name}.{foreign_key.column.name}"
                        ),
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
