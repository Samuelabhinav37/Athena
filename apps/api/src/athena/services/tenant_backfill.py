import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.models import Base, Tenant
from athena.services.tenant_inventory import capture_tenant_inventory
from athena.tenant_transition import (
    IMMUTABLE_EVIDENCE_TABLES,
    TENANT_TABLES,
    BootstrapTenantApproval,
    TenantTransitionError,
    validate_observed_inventory,
)


class TenantBackfillPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["dry_run"] = "dry_run"
    database_mutation: Literal[False] = False
    tenant_id: str
    approval_reference: str
    inventory_sha256: str
    total_rows: int
    table_counts: dict[str, int]
    immutable_evidence_tables: tuple[str, ...]
    operations: tuple[str, ...]
    plan_sha256: str


def load_bootstrap_approval(path: Path) -> BootstrapTenantApproval:
    return BootstrapTenantApproval.model_validate_json(path.read_text(encoding="utf-8"))


def build_bootstrap_backfill_plan(
    session: Session, approval: BootstrapTenantApproval
) -> TenantBackfillPlan:
    snapshot = capture_tenant_inventory(session)
    validate_observed_inventory(approval, snapshot.table_counts)

    existing_tenant = session.get(Tenant, approval.tenant_id)
    if existing_tenant is not None:
        raise TenantTransitionError("Approved bootstrap tenant already exists")

    assigned_counts: dict[str, int] = {}
    with session.no_autoflush:
        for table_name in TENANT_TABLES:
            table = Base.metadata.tables[table_name]
            assigned_counts[table_name] = int(
                session.scalar(
                    select(func.count()).select_from(table).where(table.c.tenant_id.is_not(None))
                )
                or 0
            )
    assigned_counts = {table: count for table, count in assigned_counts.items() if count}
    if assigned_counts:
        raise TenantTransitionError(
            "Tenant backfill requires every scoped row to be unassigned; "
            f"assigned={assigned_counts}"
        )

    operations = (
        f"Create tenant registry record {approval.tenant_id!r} from the approved artifact.",
        f"Assign {snapshot.total_rows} existing rows across {len(TENANT_TABLES)} tables.",
        "Recount every table and verify that only tenant_id changed.",
        "Verify every scoped row belongs to the approved bootstrap tenant.",
    )
    facts = {
        "schema_version": "1.0",
        "status": "dry_run",
        "database_mutation": False,
        "tenant_id": approval.tenant_id,
        "approval_reference": approval.approval_reference,
        "inventory_sha256": snapshot.inventory_sha256,
        "total_rows": snapshot.total_rows,
        "table_counts": snapshot.table_counts,
        "immutable_evidence_tables": IMMUTABLE_EVIDENCE_TABLES,
        "operations": operations,
    }
    digest = hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return TenantBackfillPlan(**facts, plan_sha256=digest)
