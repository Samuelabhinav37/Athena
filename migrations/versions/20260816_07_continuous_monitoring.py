"""Create durable continuous monitoring run history.

Revision ID: 20260816_07
Revises: 20260816_06
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260816_07"
down_revision = "20260816_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    status = sa.Enum(
        "pending", "running", "completed", "failed", name="monitoring_status", native_enum=False
    )
    step_status = sa.Enum(
        "pending",
        "running",
        "completed",
        "failed",
        name="monitoring_step_status",
        native_enum=False,
    )
    op.create_table(
        "monitoring_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("schedule_key", sa.String(255), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("summary", jsonb, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("schedule_key", name="uq_monitoring_run_schedule_key"),
    )
    op.create_index(op.f("ix_monitoring_runs_started_at"), "monitoring_runs", ["started_at"])
    op.create_table(
        "monitoring_steps",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("status", step_status, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("output", jsonb, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["monitoring_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_monitoring_step_sequence"),
    )
    op.create_index(op.f("ix_monitoring_steps_run_id"), "monitoring_steps", ["run_id"])
    op.execute("""CREATE FUNCTION athena_prevent_monitoring_step_mutation() RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'monitoring steps are immutable'; END; $$ LANGUAGE plpgsql""")
    op.execute("""CREATE TRIGGER monitoring_steps_immutable
    BEFORE UPDATE OR DELETE ON monitoring_steps FOR EACH ROW
    EXECUTE FUNCTION athena_prevent_monitoring_step_mutation()""")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS monitoring_steps_immutable ON monitoring_steps")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_monitoring_step_mutation()")
    op.drop_table("monitoring_steps")
    op.drop_table("monitoring_runs")
