"""Create immutable peer anomaly evidence tables.

Revision ID: 20260816_05
Revises: 20260816_04
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260816_05"
down_revision = "20260816_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    op.create_table(
        "anomaly_model_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("library_version", sa.String(64), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=False),
        sa.Column(
            "trained_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("random_seed", sa.Integer(), nullable=False),
        sa.Column("contamination", sa.Float(), nullable=False),
        sa.Column("feature_schema", jsonb, nullable=False),
        sa.Column("training_fingerprint", sa.String(64), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("peer_definition", jsonb, nullable=False),
        sa.Column("summary", jsonb, nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_anomaly_model_runs_trained_at"), "anomaly_model_runs", ["trained_at"])
    op.create_index(
        op.f("ix_anomaly_model_runs_training_fingerprint"),
        "anomaly_model_runs",
        ["training_fingerprint"],
    )
    op.create_table(
        "anomaly_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=True),
        sa.Column("subject_key", sa.String(255), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("score_samples", sa.Float(), nullable=False),
        sa.Column("decision_score", sa.Float(), nullable=False),
        sa.Column("is_anomaly", sa.Boolean(), nullable=False),
        sa.Column("features", jsonb, nullable=False),
        sa.Column("explanation", jsonb, nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["anomaly_model_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "subject_key", name="uq_anomaly_result_subject"),
    )
    op.create_index(op.f("ix_anomaly_results_run_id"), "anomaly_results", ["run_id"])
    op.create_index(op.f("ix_anomaly_results_identity_id"), "anomaly_results", ["identity_id"])
    op.execute("""CREATE FUNCTION athena_prevent_anomaly_evidence_mutation() RETURNS trigger AS $$
    BEGIN RAISE EXCEPTION 'anomaly evidence is immutable'; END; $$ LANGUAGE plpgsql""")
    for table in ("anomaly_model_runs", "anomaly_results"):
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION athena_prevent_anomaly_evidence_mutation()"
        )


def downgrade() -> None:
    for table in ("anomaly_results", "anomaly_model_runs"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_anomaly_evidence_mutation()")
    op.drop_table("anomaly_results")
    op.drop_table("anomaly_model_runs")
