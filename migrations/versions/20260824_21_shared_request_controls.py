"""Add shared atomic replay and rate-limit controls.

Revision ID: 20260824_21
Revises: 20260824_20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_21"
down_revision: str | None = "20260824_20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"
SCOPED_TABLES = ("request_replays", "rate_limit_buckets")


def upgrade() -> None:
    op.create_table(
        "request_replays",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("namespace", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(63), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "namespace", "idempotency_key", name="uq_request_replays_tenant_key"
        ),
    )
    op.create_index("ix_request_replays_tenant_id", "request_replays", ["tenant_id"])
    op.create_table(
        "rate_limit_buckets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("namespace", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(63), nullable=False),
        sa.CheckConstraint("request_count > 0", name="ck_rate_limit_buckets_positive_count"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "namespace",
            "subject",
            "window_started_at",
            name="uq_rate_limit_buckets_tenant_subject_window",
        ),
    )
    op.create_index("ix_rate_limit_buckets_tenant_id", "rate_limit_buckets", ["tenant_id"])
    for table in SCOPED_TABLES:
        op.execute(f'GRANT SELECT ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" TO athena_app '
            f"USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )
    op.execute('GRANT INSERT ON "request_replays" TO athena_app')
    op.execute('GRANT INSERT ON "rate_limit_buckets" TO athena_app')
    op.execute('GRANT UPDATE ("request_count") ON "rate_limit_buckets" TO athena_app')
    op.execute(
        """CREATE FUNCTION athena_prevent_request_replay_mutation()
        RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'request replay reservations are append-only'; END;
        $$ LANGUAGE plpgsql"""
    )
    op.execute(
        """CREATE TRIGGER request_replays_immutable
        BEFORE UPDATE OR DELETE ON request_replays FOR EACH ROW
        EXECUTE FUNCTION athena_prevent_request_replay_mutation()"""
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS request_replays_immutable ON request_replays")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_request_replay_mutation()")
    op.drop_table("rate_limit_buckets")
    op.drop_table("request_replays")
