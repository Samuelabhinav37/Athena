"""Create remediation review workflow tables.

Revision ID: 20260816_06
Revises: 20260816_05
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260816_06"
down_revision = "20260816_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    status = sa.Enum(
        "open", "in_review", "resolved", "cancelled", name="review_status", native_enum=False
    )
    decision = sa.Enum(
        "retain", "revoke", "extend", "exception", name="review_decision", native_enum=False
    )
    event_from = sa.Enum(
        "open",
        "in_review",
        "resolved",
        "cancelled",
        name="review_event_from_status",
        native_enum=False,
    )
    event_to = sa.Enum(
        "open",
        "in_review",
        "resolved",
        "cancelled",
        name="review_event_to_status",
        native_enum=False,
    )
    event_decision = sa.Enum(
        "retain", "revoke", "extend", "exception", name="review_event_decision", native_enum=False
    )
    op.create_table(
        "review_cases",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=True),
        sa.Column("risk_assessment_id", sa.Uuid(), nullable=True),
        sa.Column("anomaly_result_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolution", decision, nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "risk_assessment_id IS NOT NULL OR anomaly_result_id IS NOT NULL",
            name="ck_review_case_has_evidence",
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["risk_assessment_id"], ["risk_assessments.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["anomaly_result_id"], ["anomaly_results.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "identity_id",
        "entitlement_id",
        "risk_assessment_id",
        "anomaly_result_id",
        "owner",
        "due_at",
    ):
        op.create_index(op.f(f"ix_review_cases_{column}"), "review_cases", [column])
    op.create_table(
        "review_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.Uuid(), nullable=False),
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
        sa.Column("decision", event_decision, nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence_snapshot", jsonb, nullable=False),
        sa.Column("execution_status", sa.String(32), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["review_cases.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_review_events_case_id"), "review_events", ["case_id"])
    op.execute("""CREATE FUNCTION athena_prevent_review_event_mutation() RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'review events are immutable'; END; $$ LANGUAGE plpgsql""")
    op.execute("""CREATE TRIGGER review_events_immutable BEFORE UPDATE OR DELETE ON review_events
    FOR EACH ROW EXECUTE FUNCTION athena_prevent_review_event_mutation()""")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS review_events_immutable ON review_events")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_review_event_mutation()")
    op.drop_table("review_events")
    op.drop_table("review_cases")
