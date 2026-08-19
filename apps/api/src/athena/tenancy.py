from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

TENANT_CONTRACT_VERSION = "1.0"
TENANT_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{2,62}$"


class TenantIsolationError(PermissionError):
    pass


class TenantContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[TENANT_CONTRACT_VERSION] = TENANT_CONTRACT_VERSION
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    subject: str = Field(min_length=1, max_length=255)
    source: Literal["oidc_claim", "service_identity", "system_job"]

    @field_validator("tenant_id")
    @classmethod
    def require_canonical_tenant_id(cls, value: str) -> str:
        if value != value.lower():
            raise ValueError("tenant_id must be canonical lowercase")
        return value


class TenantScopedReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    object_type: Literal[
        "identity",
        "group",
        "role",
        "resource",
        "grant",
        "entitlement",
        "policy_evaluation",
        "risk_assessment",
        "review",
        "execution",
        "monitoring_run",
        "connector_checkpoint",
        "audit_event",
        "report",
    ]
    object_id: str = Field(min_length=1, max_length=255)


class TenantIsolationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[TENANT_CONTRACT_VERSION] = TENANT_CONTRACT_VERSION
    status: Literal["design_only"] = "design_only"
    current_mode: Literal["single_tenant"] = "single_tenant"
    target_mode: Literal["shared_database_row_isolation"] = "shared_database_row_isolation"
    tenant_claim: Literal["athena_tenant_id"] = "athena_tenant_id"
    global_administrator_bypass: Literal[False] = False
    invariants: tuple[str, ...]
    migration_entities: tuple[str, ...]
    blockers: tuple[str, ...]


TENANT_ISOLATION_PLAN = TenantIsolationPlan(
    invariants=(
        "Every persisted business and evidence row has one non-null Athena tenant key.",
        "Every uniqueness constraint includes the Athena tenant key unless data is global.",
        "Every request and background job has one validated tenant context before data access.",
        "Cross-tenant reads, writes, joins, references, cache keys, and exports fail closed.",
        "Append-only evidence immutability remains enforced inside each tenant boundary.",
        "Source tenant identifiers are evidence attributes and never Athena tenant authority.",
        "No administrator role bypasses tenant isolation.",
    ),
    migration_entities=(
        "identities",
        "groups",
        "roles",
        "resources",
        "permissions",
        "access_grants",
        "effective_entitlements",
        "provenance_edges",
        "policy_evaluations",
        "risk_assessments",
        "anomaly_results",
        "review_cases_and_events",
        "remediation_executions_and_events",
        "monitoring_runs_and_steps",
        "connector_checkpoints",
        "audit_events",
        "derived_graph_nodes_and_edges",
        "report_and_export_artifacts",
    ),
    blockers=(
        "Choose and document the authoritative OIDC tenant claim and issuer binding.",
        "Design a non-destructive backfill for every existing row before non-null enforcement.",
        "Add composite foreign keys and tenant-aware uniqueness constraints in a reviewed "
        "migration.",
        "Add database row-level security with transaction-local tenant context and "
        "fail-closed pooling.",
        "Make every query, cache key, job key, connector scope, and graph projection tenant-aware.",
        "Add cross-tenant negative tests at ORM, SQL, API, job, export, and graph boundaries.",
        "Define tenant-scoped encryption, backup, restore, retention, deletion, and "
        "residency controls.",
    ),
)


def require_tenant_access(
    context: TenantContext, reference: TenantScopedReference
) -> TenantScopedReference:
    if context.tenant_id != reference.tenant_id:
        raise TenantIsolationError("Cross-tenant access is forbidden")
    return reference
