"""Add the tenant registry and nullable tenant scope.

Revision ID: 20260820_10
Revises: 20260817_09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_10"
down_revision: str | None = "20260817_09"
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


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=63), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("approval_reference", sa.String(length=255), nullable=False),
        sa.Column("authorized_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("inventory_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for table_name in SCOPED_TABLES:
        op.add_column(table_name, sa.Column("tenant_id", sa.String(length=63), nullable=True))
        op.create_foreign_key(
            f"fk_{table_name}_tenant_id_tenants",
            table_name,
            "tenants",
            ["tenant_id"],
            ["id"],
        )
        op.create_index(f"ix_{table_name}_tenant_id", table_name, ["tenant_id"], unique=False)


def downgrade() -> None:
    for table_name in reversed(SCOPED_TABLES):
        op.drop_index(f"ix_{table_name}_tenant_id", table_name=table_name)
        op.drop_constraint(f"fk_{table_name}_tenant_id_tenants", table_name, type_="foreignkey")
        op.drop_column(table_name, "tenant_id")
    op.drop_table("tenants")
