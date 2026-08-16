"""Create identity drift and explainable risk analytics tables.

Revision ID: 20260816_04
Revises: 20260816_03
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260816_04"
down_revision: str | None = "20260816_03"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    metadata_type = postgresql.JSONB(astext_type=sa.Text())
    risk_level = sa.Enum(
        "low", "medium", "high", "critical", name="risk_level", native_enum=False
    )
    finding_type = sa.Enum(
        "retained_access",
        "peer_deviation",
        "stale_access",
        "policy_violation",
        name="risk_finding_type",
        native_enum=False,
    )
    op.create_table(
        "role_transitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("from_department", sa.String(length=128), nullable=True),
        sa.Column("to_department", sa.String(length=128), nullable=True),
        sa.Column("from_roles", metadata_type, nullable=False),
        sa.Column("to_roles", metadata_type, nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("actor_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_role_transitions_identity_id"), "role_transitions", ["identity_id"]
    )
    op.create_table(
        "access_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("usage_count", sa.Integer(), nullable=False),
        sa.Column("source_metadata", metadata_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source", "external_id", name="uq_access_observation_source_external"
        ),
    )
    op.create_index(
        op.f("ix_access_observations_entitlement_id"),
        "access_observations",
        ["entitlement_id"],
    )
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("level", risk_level, nullable=False),
        sa.Column("peer_definition", metadata_type, nullable=False),
        sa.Column("summary", metadata_type, nullable=False),
        sa.CheckConstraint(
            "score >= 0 AND score <= 100", name="ck_risk_assessment_score_range"
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_assessments_evaluated_at"), "risk_assessments", ["evaluated_at"]
    )
    op.create_index(
        op.f("ix_risk_assessments_identity_id"), "risk_assessments", ["identity_id"]
    )
    op.create_table(
        "risk_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column("finding_type", finding_type, nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("factors", metadata_type, nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "score >= 0 AND score <= 100", name="ck_risk_finding_score_range"
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["risk_assessments.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_findings_assessment_id"), "risk_findings", ["assessment_id"]
    )
    op.execute(
        """
        CREATE FUNCTION athena_prevent_role_transition_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'role_transitions is immutable';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER role_transitions_immutable
        BEFORE UPDATE OR DELETE ON role_transitions
        FOR EACH ROW EXECUTE FUNCTION athena_prevent_role_transition_mutation()
        """
    )
    op.execute(
        """
        CREATE FUNCTION athena_prevent_risk_assessment_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'risk_assessments is immutable';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER risk_assessments_immutable
        BEFORE UPDATE OR DELETE ON risk_assessments
        FOR EACH ROW EXECUTE FUNCTION athena_prevent_risk_assessment_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS risk_assessments_immutable ON risk_assessments")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_risk_assessment_mutation()")
    op.execute("DROP TRIGGER IF EXISTS role_transitions_immutable ON role_transitions")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_role_transition_mutation()")
    op.drop_index(op.f("ix_risk_findings_assessment_id"), table_name="risk_findings")
    op.drop_table("risk_findings")
    op.drop_index(op.f("ix_risk_assessments_identity_id"), table_name="risk_assessments")
    op.drop_index(op.f("ix_risk_assessments_evaluated_at"), table_name="risk_assessments")
    op.drop_table("risk_assessments")
    op.drop_index(
        op.f("ix_access_observations_entitlement_id"), table_name="access_observations"
    )
    op.drop_table("access_observations")
    op.drop_index(op.f("ix_role_transitions_identity_id"), table_name="role_transitions")
    op.drop_table("role_transitions")
