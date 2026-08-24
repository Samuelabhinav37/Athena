"""Persist approved tenant-to-provider connector scope bindings.

Revision ID: 20260824_15
Revises: 20260824_14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_15"
down_revision: str | None = "20260824_14"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"
SCOPED_TABLES = ("connector_scope_bindings",)


def upgrade() -> None:
    op.create_table(
        "connector_scope_bindings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connector", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=255), nullable=False),
        sa.Column("approval_reference", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=63), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.CheckConstraint(
            "connector = lower(connector)", name="ck_connector_scope_connector_lower"
        ),
        sa.CheckConstraint("scope = lower(scope)", name="ck_connector_scope_scope_lower"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "id", name="uq_connector_scope_bindings_tenant_id"
        ),
        sa.UniqueConstraint(
            "connector", "scope", name="uq_connector_scope_bindings_connector_scope"
        ),
    )
    op.create_index(
        op.f("ix_connector_scope_bindings_tenant_id"),
        "connector_scope_bindings",
        ["tenant_id"],
        unique=False,
    )
    for table in SCOPED_TABLES:
        op.execute(f'GRANT SELECT ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            f"TO athena_app USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )


def downgrade() -> None:
    for table in reversed(SCOPED_TABLES):
        op.execute(f'DROP POLICY "{table}_tenant_isolation" ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        op.execute(f'REVOKE SELECT ON "{table}" FROM athena_app')
    op.drop_index(
        op.f("ix_connector_scope_bindings_tenant_id"),
        table_name="connector_scope_bindings",
    )
    op.drop_table("connector_scope_bindings")
