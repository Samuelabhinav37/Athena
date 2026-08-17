"""Create authorized remediation execution evidence.

Revision ID: 20260817_09
Revises: 20260816_08
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260817_09"
down_revision = "20260816_08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    status = sa.Enum(
        "pending",
        "running",
        "succeeded",
        "failed",
        "verification_failed",
        name="remediation_execution_status",
        native_enum=False,
    )
    event_from = sa.Enum(
        "pending",
        "running",
        "succeeded",
        "failed",
        "verification_failed",
        name="remediation_event_from_status",
        native_enum=False,
    )
    event_to = sa.Enum(
        "pending",
        "running",
        "succeeded",
        "failed",
        "verification_failed",
        name="remediation_event_to_status",
        native_enum=False,
    )
    op.create_table(
        "remediation_executions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("target_external_id", sa.String(255), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("before_evidence", jsonb, nullable=False),
        sa.Column("after_evidence", jsonb, nullable=False),
        sa.Column("adapter_receipt", jsonb, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["case_id"], ["review_cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", name="uq_remediation_execution_case"),
        sa.UniqueConstraint("idempotency_key", name="uq_remediation_execution_idempotency"),
    )
    op.create_index(
        op.f("ix_remediation_executions_case_id"), "remediation_executions", ["case_id"]
    )
    op.create_index(
        op.f("ix_remediation_executions_source"), "remediation_executions", ["source"]
    )
    op.create_table(
        "remediation_execution_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("execution_id", sa.Uuid(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("from_status", event_from, nullable=True),
        sa.Column("to_status", event_to, nullable=False),
        sa.Column("evidence", jsonb, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["execution_id"], ["remediation_executions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_remediation_execution_events_execution_id"),
        "remediation_execution_events",
        ["execution_id"],
    )
    op.execute("""CREATE FUNCTION athena_prevent_remediation_event_mutation() RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'remediation execution events are immutable'; END; $$ LANGUAGE plpgsql""")
    op.execute("""CREATE TRIGGER remediation_execution_events_immutable
    BEFORE UPDATE OR DELETE ON remediation_execution_events
    FOR EACH ROW EXECUTE FUNCTION athena_prevent_remediation_event_mutation()""")


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS remediation_execution_events_immutable "
        "ON remediation_execution_events"
    )
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_remediation_event_mutation()")
    op.drop_table("remediation_execution_events")
    op.drop_table("remediation_executions")
