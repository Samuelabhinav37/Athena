"""Create immutable deterministic policy evaluation evidence.

Revision ID: 20260816_03
Revises: 20260816_02
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260816_03"
down_revision: str | None = "20260816_02"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    metadata_type = postgresql.JSONB(astext_type=sa.Text())
    decision = sa.Enum(
        "pass",
        "fail",
        "error",
        name="policy_decision",
        native_enum=False,
    )
    op.add_column(
        "effective_entitlements",
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.add_column(
        "effective_entitlements",
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "policy_evaluations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("engine", sa.String(length=64), nullable=False),
        sa.Column("policy_path", sa.String(length=255), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("decision", decision, nullable=False),
        sa.Column("input_snapshot", metadata_type, nullable=False),
        sa.Column("violations", metadata_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_policy_evaluations_entitlement_id"),
        "policy_evaluations",
        ["entitlement_id"],
    )
    op.create_index(
        op.f("ix_policy_evaluations_evaluated_at"),
        "policy_evaluations",
        ["evaluated_at"],
    )
    op.create_index(
        op.f("ix_policy_evaluations_policy_version"),
        "policy_evaluations",
        ["policy_version"],
    )
    op.execute(
        """
        CREATE FUNCTION athena_prevent_policy_evaluation_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'policy_evaluations is immutable';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER policy_evaluations_immutable
        BEFORE UPDATE OR DELETE ON policy_evaluations
        FOR EACH ROW EXECUTE FUNCTION athena_prevent_policy_evaluation_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS policy_evaluations_immutable ON policy_evaluations")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_policy_evaluation_mutation()")
    op.drop_index(
        op.f("ix_policy_evaluations_policy_version"), table_name="policy_evaluations"
    )
    op.drop_index(
        op.f("ix_policy_evaluations_evaluated_at"), table_name="policy_evaluations"
    )
    op.drop_index(
        op.f("ix_policy_evaluations_entitlement_id"), table_name="policy_evaluations"
    )
    op.drop_table("policy_evaluations")
    op.drop_column("effective_entitlements", "deactivated_at")
    op.drop_column("effective_entitlements", "active")
