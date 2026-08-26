"""Version immutable effective-entitlement provenance lineage.

Revision ID: 20260824_19
Revises: 20260824_18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_19"
down_revision: str | None = "20260824_18"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "effective_entitlements",
        sa.Column("lineage_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.drop_constraint(
        "uq_effective_entitlements_tenant_identity_id_grant_id",
        "effective_entitlements",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_effective_entitlements_tenant_identity_grant_version",
        "effective_entitlements",
        ["tenant_id", "identity_id", "grant_id", "lineage_version"],
    )
    op.create_index(
        "uq_effective_entitlements_one_active_lineage",
        "effective_entitlements",
        ["tenant_id", "identity_id", "grant_id"],
        unique=True,
        postgresql_where=sa.text("active"),
    )
    op.execute('REVOKE DELETE ON "effective_entitlements" FROM athena_app')


def downgrade() -> None:
    op.execute('GRANT DELETE ON "effective_entitlements" TO athena_app')
    op.drop_index(
        "uq_effective_entitlements_one_active_lineage",
        table_name="effective_entitlements",
    )
    op.drop_constraint(
        "uq_effective_entitlements_tenant_identity_grant_version",
        "effective_entitlements",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_effective_entitlements_tenant_identity_id_grant_id",
        "effective_entitlements",
        ["tenant_id", "identity_id", "grant_id"],
    )
    op.drop_column("effective_entitlements", "lineage_version")
