"""Preserve append-only connector scope revocations.

Revision ID: 20260824_17
Revises: 20260824_16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_17"
down_revision: str | None = "20260824_16"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"
SCOPED_TABLES = ("connector_scope_revocations",)
TABLE = SCOPED_TABLES[0]


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("binding_id", sa.Uuid(), nullable=False),
        sa.Column("approval_reference", sa.String(length=255), nullable=False),
        sa.Column("revoked_by", sa.String(length=255), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("tenant_id", sa.String(length=63), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(
            ["tenant_id", "binding_id"],
            ["connector_scope_bindings.tenant_id", "connector_scope_bindings.id"],
            name="fk_connector_scope_revocations_tenant_binding_id_bindings",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "binding_id",
            name="uq_connector_scope_revocations_tenant_binding_id",
        ),
    )
    op.create_index(
        op.f("ix_connector_scope_revocations_tenant_id"),
        TABLE,
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
    op.execute(
        """CREATE FUNCTION athena_prevent_connector_scope_revocation_mutation()
        RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'connector scope revocations are immutable'; END;
        $$ LANGUAGE plpgsql"""
    )
    op.execute(
        f"""CREATE TRIGGER {TABLE}_immutable
        BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW
        EXECUTE FUNCTION athena_prevent_connector_scope_revocation_mutation()"""
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS {TABLE}_immutable ON {TABLE}")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_connector_scope_revocation_mutation()")
    op.execute(f'DROP POLICY "{TABLE}_tenant_isolation" ON "{TABLE}"')
    op.execute(f'ALTER TABLE "{TABLE}" NO FORCE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{TABLE}" DISABLE ROW LEVEL SECURITY')
    op.execute(f'REVOKE SELECT ON "{TABLE}" FROM athena_app')
    op.drop_index(op.f("ix_connector_scope_revocations_tenant_id"), table_name=TABLE)
    op.drop_table(TABLE)
