import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import ForeignKeyConstraint, UniqueConstraint

from athena.models import Base
from athena.services.tenant_integrity import TenantIntegrityReport
from athena.tenant_transition import TENANT_TABLES


class TenantUniqueConstraintChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    table: str
    current_name: str
    current_columns: tuple[str, ...]
    proposed_name: str
    proposed_columns: tuple[str, ...]


class TenantForeignKeyChange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    child_table: str
    current_name: str
    current_columns: tuple[str, ...]
    parent_table: str
    parent_columns: tuple[str, ...]
    proposed_name: str
    proposed_child_columns: tuple[str, ...]
    proposed_parent_columns: tuple[str, ...]
    ondelete: str | None


class TenantSupportingUniqueConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    table: str
    proposed_name: str
    proposed_columns: tuple[str, ...]


class TenantConstraintPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ready", "blocked_by_integrity"]
    database_mutation: Literal[False] = False
    unique_changes: tuple[TenantUniqueConstraintChange, ...]
    foreign_key_changes: tuple[TenantForeignKeyChange, ...]
    supporting_unique_constraints: tuple[TenantSupportingUniqueConstraint, ...]
    plan_sha256: str


def _constraint_name(prefix: str, *parts: str) -> str:
    candidate = "_".join((prefix, *parts))
    if len(candidate) <= 63:
        return candidate
    suffix = hashlib.sha256(candidate.encode()).hexdigest()[:8]
    return f"{candidate[:54]}_{suffix}"


def _build_tenant_constraint_plan(*, ready: bool) -> TenantConstraintPlan:
    unique_changes: list[TenantUniqueConstraintChange] = []
    foreign_key_changes: list[TenantForeignKeyChange] = []
    supporting: dict[tuple[str, ...], TenantSupportingUniqueConstraint] = {}

    for table_name in TENANT_TABLES:
        table = Base.metadata.tables[table_name]
        for constraint in table.constraints:
            if not isinstance(constraint, UniqueConstraint) or "tenant_id" in constraint.columns:
                continue
            columns = tuple(column.name for column in constraint.columns)
            unique_changes.append(
                TenantUniqueConstraintChange(
                    table=table_name,
                    current_name=str(constraint.name),
                    current_columns=columns,
                    proposed_name=_constraint_name("uq", table_name, "tenant", *columns),
                    proposed_columns=("tenant_id", *columns),
                )
            )

        for foreign_key in table.foreign_key_constraints:
            if not isinstance(foreign_key, ForeignKeyConstraint):
                continue
            elements = tuple(foreign_key.elements)
            parent = elements[0].column.table
            if parent.name not in TENANT_TABLES:
                continue
            child_columns = tuple(element.parent.name for element in elements)
            parent_columns = tuple(element.column.name for element in elements)
            if "tenant_id" in child_columns:
                continue
            current_name = foreign_key.name or _constraint_name(
                "fk", table_name, *child_columns, parent.name
            )
            foreign_key_changes.append(
                TenantForeignKeyChange(
                    child_table=table_name,
                    current_name=current_name,
                    current_columns=child_columns,
                    parent_table=parent.name,
                    parent_columns=parent_columns,
                    proposed_name=_constraint_name(
                        "fk", table_name, "tenant", *child_columns, parent.name
                    ),
                    proposed_child_columns=("tenant_id", *child_columns),
                    proposed_parent_columns=("tenant_id", *parent_columns),
                    ondelete=foreign_key.ondelete,
                )
            )
            supporting[(parent.name, *parent_columns)] = TenantSupportingUniqueConstraint(
                table=parent.name,
                proposed_name=_constraint_name("uq", parent.name, "tenant", *parent_columns),
                proposed_columns=("tenant_id", *parent_columns),
            )

    unique_changes.sort(key=lambda change: (change.table, change.current_name))
    foreign_key_changes.sort(key=lambda change: (change.child_table, change.current_name))
    supporting_constraints = tuple(
        sorted(supporting.values(), key=lambda constraint: constraint.proposed_name)
    )
    facts = {
        "schema_version": "1.0",
        "status": "ready" if ready else "blocked_by_integrity",
        "database_mutation": False,
        "unique_changes": [change.model_dump(mode="json") for change in unique_changes],
        "foreign_key_changes": [change.model_dump(mode="json") for change in foreign_key_changes],
        "supporting_unique_constraints": [
            constraint.model_dump(mode="json") for constraint in supporting_constraints
        ],
    }
    digest = hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return TenantConstraintPlan(**facts, plan_sha256=digest)


def build_tenant_constraint_plan(integrity: TenantIntegrityReport) -> TenantConstraintPlan:
    return _build_tenant_constraint_plan(ready=integrity.ready_for_tenant_constraints)


def is_complete_tenant_constraint_plan(plan: TenantConstraintPlan) -> bool:
    return plan == _build_tenant_constraint_plan(ready=plan.status == "ready")
