import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, insert, select, text, update
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


class TenantBackfillResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["completed"] = "completed"
    tenant_id: str
    approval_reference: str
    plan_sha256: str
    inventory_sha256: str
    assigned_rows: int
    assigned_table_counts: dict[str, int]


_IMMUTABLE_FUNCTIONS = {
    "athena_prevent_audit_event_mutation": "audit_events is append-only",
    "athena_prevent_policy_evaluation_mutation": "policy_evaluations is immutable",
    "athena_prevent_role_transition_mutation": "role_transitions is immutable",
    "athena_prevent_risk_assessment_mutation": "risk_assessments is immutable",
    "athena_prevent_anomaly_evidence_mutation": "anomaly evidence is immutable",
    "athena_prevent_review_event_mutation": "review events are immutable",
    "athena_prevent_monitoring_step_mutation": "monitoring steps are immutable",
    "athena_prevent_remediation_event_mutation": "remediation execution events are immutable",
}


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


def _set_immutable_trigger_mode(session: Session, *, allow_bootstrap: bool) -> None:
    for function_name, error_message in _IMMUTABLE_FUNCTIONS.items():
        body = ""
        if allow_bootstrap:
            body = """
                IF TG_OP = 'UPDATE'
                   AND OLD.tenant_id IS NULL
                   AND NEW.tenant_id = current_setting('athena.bootstrap_tenant_id', true)
                   AND (to_jsonb(NEW) - 'tenant_id') = (to_jsonb(OLD) - 'tenant_id') THEN
                    RETURN NEW;
                END IF;
            """
        statement = f"""
            CREATE OR REPLACE FUNCTION {function_name}()
            RETURNS trigger AS $$
            BEGIN
                {body}
                RAISE EXCEPTION '{error_message}';
            END;
            $$ LANGUAGE plpgsql
        """
        session.execute(text(statement))


def execute_bootstrap_backfill(
    session: Session,
    approval: BootstrapTenantApproval,
    *,
    confirmed_plan_sha256: str,
) -> TenantBackfillResult:
    if session.bind is None or session.bind.dialect.name != "postgresql":
        raise TenantTransitionError("Executable tenant backfill requires PostgreSQL")

    lock_targets = ", ".join(("tenants", *TENANT_TABLES))
    session.execute(text(f"LOCK TABLE {lock_targets} IN ACCESS EXCLUSIVE MODE"))
    plan = build_bootstrap_backfill_plan(session, approval)
    if confirmed_plan_sha256 != plan.plan_sha256:
        raise TenantTransitionError(
            "Confirmed plan digest does not match the current backfill plan"
        )

    session.execute(
        text("SELECT set_config('athena.bootstrap_tenant_id', :tenant_id, true)"),
        {"tenant_id": approval.tenant_id},
    )
    now = datetime.now(UTC)
    session.execute(
        insert(Tenant).values(
            id=approval.tenant_id,
            display_name=approval.display_name,
            approval_reference=approval.approval_reference,
            authorized_by=approval.authorized_by,
            approved_at=approval.approved_at,
            inventory_sha256=approval.inventory_sha256,
            created_at=now,
            updated_at=now,
        )
    )

    assigned: dict[str, int] = {}
    _set_immutable_trigger_mode(session, allow_bootstrap=True)
    try:
        for table_name in TENANT_TABLES:
            table = Base.metadata.tables[table_name]
            result = session.execute(
                update(table)
                .where(table.c.tenant_id.is_(None))
                .values(tenant_id=approval.tenant_id)
            )
            assigned[table_name] = result.rowcount
    finally:
        _set_immutable_trigger_mode(session, allow_bootstrap=False)

    if assigned != plan.table_counts:
        raise TenantTransitionError(
            f"Backfill assignment counts differ from the approved plan; assigned={assigned}"
        )
    for table_name in TENANT_TABLES:
        table = Base.metadata.tables[table_name]
        invalid = session.scalar(
            select(func.count())
            .select_from(table)
            .where(table.c.tenant_id.is_distinct_from(approval.tenant_id))
        )
        if invalid:
            raise TenantTransitionError(f"Backfill verification failed for table {table_name}")

    snapshot = capture_tenant_inventory(session)
    validate_observed_inventory(approval, snapshot.table_counts)
    return TenantBackfillResult(
        tenant_id=approval.tenant_id,
        approval_reference=approval.approval_reference,
        plan_sha256=plan.plan_sha256,
        inventory_sha256=snapshot.inventory_sha256,
        assigned_rows=sum(assigned.values()),
        assigned_table_counts=assigned,
    )
