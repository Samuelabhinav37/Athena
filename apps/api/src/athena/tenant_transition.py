import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena.tenancy import TENANT_CONTRACT_VERSION, TENANT_ID_PATTERN

TENANT_TRANSITION_VERSION = "1.0"
TENANT_TABLES = (
    "access_grants",
    "access_observations",
    "anomaly_model_runs",
    "anomaly_results",
    "audit_events",
    "connector_checkpoints",
    "effective_entitlements",
    "groups",
    "identities",
    "identity_groups",
    "identity_roles",
    "monitoring_runs",
    "monitoring_steps",
    "permissions",
    "policy_evaluations",
    "provenance_edges",
    "remediation_execution_events",
    "remediation_executions",
    "resources",
    "review_cases",
    "review_events",
    "risk_assessments",
    "risk_findings",
    "role_transitions",
    "roles",
)
IMMUTABLE_EVIDENCE_TABLES = (
    "access_observations",
    "anomaly_model_runs",
    "anomaly_results",
    "audit_events",
    "monitoring_runs",
    "monitoring_steps",
    "policy_evaluations",
    "provenance_edges",
    "remediation_execution_events",
    "review_events",
    "risk_assessments",
    "risk_findings",
    "role_transitions",
)


class TenantTransitionError(ValueError):
    pass


class BootstrapTenantApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=255)
    approval_reference: str = Field(min_length=8, max_length=255)
    authorized_by: str = Field(min_length=1, max_length=255)
    approved_at: datetime
    expected_preexisting_rows: dict[str, int]
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("approved_at")
    @classmethod
    def require_aware_approval_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approved_at must include a timezone")
        return value

    @field_validator("expected_preexisting_rows")
    @classmethod
    def require_complete_nonnegative_inventory(cls, value: dict[str, int]) -> dict[str, int]:
        if set(value) != set(TENANT_TABLES):
            missing = sorted(set(TENANT_TABLES) - set(value))
            extra = sorted(set(value) - set(TENANT_TABLES))
            raise ValueError(f"inventory table mismatch; missing={missing}, extra={extra}")
        if any(isinstance(count, bool) or count < 0 for count in value.values()):
            raise ValueError("inventory counts must be non-negative integers")
        return dict(sorted(value.items()))

    @model_validator(mode="after")
    def require_matching_inventory_digest(self) -> "BootstrapTenantApproval":
        if tenant_inventory_digest(self.expected_preexisting_rows) != self.inventory_sha256:
            raise ValueError("inventory_sha256 does not match expected_preexisting_rows")
        return self


class TenantTransitionPhase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    phase_id: str
    description: str
    required_checks: tuple[str, ...] = Field(min_length=1)
    database_mutation: bool


class TenantTransitionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    transition_version: Literal[TENANT_TRANSITION_VERSION] = TENANT_TRANSITION_VERSION
    tenant_contract_version: Literal[TENANT_CONTRACT_VERSION] = TENANT_CONTRACT_VERSION
    status: Literal["review_required"] = "review_required"
    bootstrap: BootstrapTenantApproval
    tables: tuple[str, ...]
    immutable_evidence_tables: tuple[str, ...]
    phases: tuple[TenantTransitionPhase, ...]
    plan_sha256: str

    @model_validator(mode="after")
    def validate_plan_shape(self) -> "TenantTransitionPlan":
        if self.tables != TENANT_TABLES:
            raise ValueError("transition plan does not cover the canonical tenant table set")
        if [phase.sequence for phase in self.phases] != list(range(1, len(self.phases) + 1)):
            raise ValueError("transition phases must be contiguous and ordered")
        return self


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def tenant_inventory_digest(table_counts: dict[str, int]) -> str:
    facts = {
        "schema_version": "1.0",
        "table_counts": dict(sorted(table_counts.items())),
        "total_rows": sum(table_counts.values()),
    }
    return hashlib.sha256(_canonical(facts)).hexdigest()


def build_tenant_transition_plan(bootstrap: BootstrapTenantApproval) -> TenantTransitionPlan:
    phases = (
        TenantTransitionPhase(
            sequence=1,
            phase_id="freeze-and-inventory",
            description="Pause writers and compare every table count with the approved inventory.",
            required_checks=(
                "No application, collector, monitor, or remediation writer is active.",
                "Observed row counts exactly match the approved preexisting inventory.",
                "A recoverable encrypted backup and restore rehearsal are current.",
            ),
            database_mutation=False,
        ),
        TenantTransitionPhase(
            sequence=2,
            phase_id="add-bootstrap-scope",
            description=(
                "Add tenant keys using the approved bootstrap constant without ORM evidence "
                "updates."
            ),
            required_checks=(
                "All existing rows receive exactly the approved bootstrap tenant ID.",
                "Immutable evidence triggers and application listeners remain enabled.",
                "No row content other than the new tenant key changes.",
            ),
            database_mutation=True,
        ),
        TenantTransitionPhase(
            sequence=3,
            phase_id="tenant-aware-integrity",
            description="Replace global references and uniqueness with tenant-aware constraints.",
            required_checks=(
                "Every foreign-key relationship proves matching tenant ownership.",
                "Every provider identifier and idempotency key is unique only inside its tenant.",
                "No orphan or cross-tenant association exists.",
            ),
            database_mutation=True,
        ),
        TenantTransitionPhase(
            sequence=4,
            phase_id="row-level-security",
            description="Add fail-closed PostgreSQL row-level security and pooled-session context.",
            required_checks=(
                "Unset tenant context returns no business or evidence rows.",
                "Reused pooled connections cannot retain the previous tenant context.",
                "Application roles cannot bypass or disable row-level security.",
            ),
            database_mutation=True,
        ),
        TenantTransitionPhase(
            sequence=5,
            phase_id="application-enforcement",
            description=(
                "Bind validated tenant context across API, jobs, connectors, exports, and graph."
            ),
            required_checks=(
                "OIDC issuer and tenant claim mapping are explicitly configured.",
                "All cache, schedule, replay, connector, artifact, and graph keys include tenant.",
                "Cross-tenant negative tests pass at every boundary.",
            ),
            database_mutation=False,
        ),
        TenantTransitionPhase(
            sequence=6,
            phase_id="enforce-and-enable",
            description=(
                "Make tenant keys non-null and enable multi-tenant runtime only after gates pass."
            ),
            required_checks=(
                "All tenant keys and composite constraints validate successfully.",
                "Full Python, migration, Rego, security, isolation, backup, and restore "
                "gates pass.",
                "A separately authorized operator approves production enablement.",
            ),
            database_mutation=True,
        ),
    )
    facts = {
        "transition_version": TENANT_TRANSITION_VERSION,
        "tenant_contract_version": TENANT_CONTRACT_VERSION,
        "status": "review_required",
        "bootstrap": bootstrap.model_dump(mode="json"),
        "tables": TENANT_TABLES,
        "immutable_evidence_tables": IMMUTABLE_EVIDENCE_TABLES,
        "phases": [phase.model_dump(mode="json") for phase in phases],
    }
    return TenantTransitionPlan(
        **facts,
        plan_sha256=hashlib.sha256(_canonical(facts)).hexdigest(),
    )


def validate_observed_inventory(
    bootstrap: BootstrapTenantApproval, observed_rows: dict[str, int]
) -> None:
    if observed_rows != bootstrap.expected_preexisting_rows:
        raise TenantTransitionError(
            "Observed row inventory differs from approved bootstrap inventory"
        )
