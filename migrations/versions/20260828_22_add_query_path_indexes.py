"""Add tenant-aware indexes for bounded query paths.

Revision ID: 20260828_22
Revises: 20260824_21
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260828_22"
down_revision: str | None = "20260824_21"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXES = (
    (
        "ix_identities_tenant_machine_page",
        "identities",
        ("tenant_id", "identity_type", "source", "username", "id"),
    ),
    (
        "ix_effective_entitlements_tenant_identity_active_computed",
        "effective_entitlements",
        ("tenant_id", "identity_id", "active", "computed_at"),
    ),
    (
        "ix_policy_evaluations_tenant_entitlement_evaluated",
        "policy_evaluations",
        ("tenant_id", "entitlement_id", "evaluated_at"),
    ),
    (
        "ix_risk_assessments_tenant_identity_evaluated",
        "risk_assessments",
        ("tenant_id", "identity_id", "evaluated_at"),
    ),
    (
        "ix_anomaly_results_tenant_identity_id",
        "anomaly_results",
        ("tenant_id", "identity_id", "id"),
    ),
    (
        "ix_review_cases_tenant_created",
        "review_cases",
        ("tenant_id", "created_at"),
    ),
    (
        "ix_remediation_executions_tenant_created",
        "remediation_executions",
        ("tenant_id", "created_at"),
    ),
    (
        "ix_monitoring_runs_tenant_started",
        "monitoring_runs",
        ("tenant_id", "started_at"),
    ),
)


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, list(columns))


def downgrade() -> None:
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
