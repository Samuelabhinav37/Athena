"""Replace global relationships and uniqueness with tenant-aware constraints.

Revision ID: 20260823_11
Revises: 20260820_10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260823_11"
down_revision: str | None = "20260820_10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCOPED_TABLES = (
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

UNIQUE_CHANGES = (
    (
        "access_grants",
        "uq_access_grant_source_external",
        "uq_access_grants_tenant_source_external_id",
        ("source", "external_id"),
    ),
    (
        "access_observations",
        "uq_access_observation_source_external",
        "uq_access_observations_tenant_source_external_id",
        ("source", "external_id"),
    ),
    (
        "anomaly_results",
        "uq_anomaly_result_subject",
        "uq_anomaly_results_tenant_run_id_subject_key",
        ("run_id", "subject_key"),
    ),
    (
        "connector_checkpoints",
        "uq_connector_checkpoint",
        "uq_connector_checkpoints_tenant_connector_scope",
        ("connector", "scope"),
    ),
    (
        "effective_entitlements",
        "uq_entitlement_identity_grant",
        "uq_effective_entitlements_tenant_identity_id_grant_id",
        ("identity_id", "grant_id"),
    ),
    (
        "groups",
        "uq_group_source_external",
        "uq_groups_tenant_source_external_id",
        ("source", "external_id"),
    ),
    (
        "identities",
        "uq_identity_source_external",
        "uq_identities_tenant_source_external_id",
        ("source", "external_id"),
    ),
    (
        "monitoring_runs",
        "uq_monitoring_run_schedule_key",
        "uq_monitoring_runs_tenant_schedule_key",
        ("schedule_key",),
    ),
    (
        "monitoring_steps",
        "uq_monitoring_step_sequence",
        "uq_monitoring_steps_tenant_run_id_sequence",
        ("run_id", "sequence"),
    ),
    (
        "permissions",
        "uq_permission_resource_action",
        "uq_permissions_tenant_resource_id_action",
        ("resource_id", "action"),
    ),
    (
        "provenance_edges",
        "uq_provenance_edge_sequence",
        "uq_provenance_edges_tenant_entitlement_id_sequence",
        ("entitlement_id", "sequence"),
    ),
    (
        "remediation_executions",
        "uq_remediation_execution_case",
        "uq_remediation_executions_tenant_case_id",
        ("case_id",),
    ),
    (
        "remediation_executions",
        "uq_remediation_execution_idempotency",
        "uq_remediation_executions_tenant_idempotency_key",
        ("idempotency_key",),
    ),
    (
        "resources",
        "uq_resource_source_external",
        "uq_resources_tenant_source_external_id",
        ("source", "external_id"),
    ),
    (
        "roles",
        "uq_role_source_external",
        "uq_roles_tenant_source_external_id",
        ("source", "external_id"),
    ),
)

FOREIGN_KEY_CHANGES = (
    ("access_grants", "approved_by_identity_id", "identities", "SET NULL"),
    ("access_grants", "group_id", "groups", "CASCADE"),
    ("access_grants", "identity_id", "identities", "CASCADE"),
    ("access_grants", "permission_id", "permissions", "CASCADE"),
    ("access_grants", "requested_by_identity_id", "identities", "SET NULL"),
    ("access_grants", "role_id", "roles", "CASCADE"),
    ("access_observations", "entitlement_id", "effective_entitlements", "CASCADE"),
    ("anomaly_results", "identity_id", "identities", "RESTRICT"),
    ("anomaly_results", "run_id", "anomaly_model_runs", "CASCADE"),
    ("effective_entitlements", "grant_id", "access_grants", "CASCADE"),
    ("effective_entitlements", "identity_id", "identities", "CASCADE"),
    ("effective_entitlements", "permission_id", "permissions", "CASCADE"),
    ("identity_groups", "group_id", "groups", "CASCADE"),
    ("identity_groups", "identity_id", "identities", "CASCADE"),
    ("identity_roles", "identity_id", "identities", "CASCADE"),
    ("identity_roles", "role_id", "roles", "CASCADE"),
    ("monitoring_steps", "run_id", "monitoring_runs", "CASCADE"),
    ("permissions", "resource_id", "resources", "CASCADE"),
    ("policy_evaluations", "entitlement_id", "effective_entitlements", "CASCADE"),
    ("provenance_edges", "entitlement_id", "effective_entitlements", "CASCADE"),
    ("remediation_execution_events", "execution_id", "remediation_executions", "CASCADE"),
    ("remediation_executions", "case_id", "review_cases", "RESTRICT"),
    ("remediation_executions", "entitlement_id", "effective_entitlements", "RESTRICT"),
    ("review_cases", "anomaly_result_id", "anomaly_results", "RESTRICT"),
    ("review_cases", "entitlement_id", "effective_entitlements", "RESTRICT"),
    ("review_cases", "identity_id", "identities", "RESTRICT"),
    ("review_cases", "risk_assessment_id", "risk_assessments", "RESTRICT"),
    ("review_events", "case_id", "review_cases", "CASCADE"),
    ("risk_assessments", "identity_id", "identities", "CASCADE"),
    ("risk_findings", "assessment_id", "risk_assessments", "CASCADE"),
    ("risk_findings", "entitlement_id", "effective_entitlements", "RESTRICT"),
    ("role_transitions", "identity_id", "identities", "CASCADE"),
)

PARENT_TABLES = tuple(sorted({parent for _, _, parent, _ in FOREIGN_KEY_CHANGES}))


def _name(prefix: str, *parts: str) -> str:
    import hashlib

    candidate = "_".join((prefix, *parts))
    if len(candidate) <= 63:
        return candidate
    return f"{candidate[:54]}_{hashlib.sha256(candidate.encode()).hexdigest()[:8]}"


def _existing_fk_name(table: str, column: str) -> str:
    foreign_keys = sa.inspect(op.get_bind()).get_foreign_keys(table)
    match = next(fk for fk in foreign_keys if fk["constrained_columns"] == [column])
    return str(match["name"])


def upgrade() -> None:
    for table in SCOPED_TABLES:
        op.alter_column(table, "tenant_id", existing_type=sa.String(length=63), nullable=False)

    for table in PARENT_TABLES:
        op.create_unique_constraint(_name("uq", table, "tenant", "id"), table, ["tenant_id", "id"])

    for child, column, parent, ondelete in FOREIGN_KEY_CHANGES:
        op.drop_constraint(_existing_fk_name(child, column), child, type_="foreignkey")
        op.create_foreign_key(
            _name("fk", child, "tenant", column, parent),
            child,
            parent,
            ["tenant_id", column],
            ["tenant_id", "id"],
            ondelete=ondelete,
        )

    for table, old_name, new_name, columns in UNIQUE_CHANGES:
        op.drop_constraint(old_name, table, type_="unique")
        op.create_unique_constraint(new_name, table, ["tenant_id", *columns])


def downgrade() -> None:
    for table, old_name, new_name, columns in reversed(UNIQUE_CHANGES):
        op.drop_constraint(new_name, table, type_="unique")
        op.create_unique_constraint(old_name, table, list(columns))

    for child, column, parent, ondelete in reversed(FOREIGN_KEY_CHANGES):
        op.drop_constraint(_name("fk", child, "tenant", column, parent), child, type_="foreignkey")
        op.create_foreign_key(None, child, parent, [column], ["id"], ondelete=ondelete)

    for table in reversed(PARENT_TABLES):
        op.drop_constraint(_name("uq", table, "tenant", "id"), table, type_="unique")

    for table in reversed(SCOPED_TABLES):
        op.alter_column(table, "tenant_id", existing_type=sa.String(length=63), nullable=True)
