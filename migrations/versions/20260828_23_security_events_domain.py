"""Create tenant-isolated browser and email security evidence domain.

Revision ID: 20260828_23
Revises: 20260828_22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260828_23"
down_revision: str | None = "20260828_22"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCOPED_TABLES = ("security_agents", "security_policy_versions", "security_events")
TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"


def upgrade() -> None:
    op.create_table(
        "security_agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("agent_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("credential_salt", sa.String(64), nullable=False),
        sa.Column("credential_digest", sa.String(128), nullable=False),
        sa.Column("enrolled_by", sa.String(255), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(63), nullable=False),
        sa.CheckConstraint("agent_type IN ('moat', 'clutter')", name="ck_security_agents_type"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_security_agents_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id", "external_id", name="uq_security_agents_tenant_external"
        ),
    )
    op.create_index("ix_security_agents_tenant_id", "security_agents", ["tenant_id"])
    op.create_index(
        "ix_security_agents_tenant_enrolled", "security_agents", ["tenant_id", "enrolled_at"]
    )

    op.create_table(
        "security_policy_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_type", sa.String(32), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column(
            "policy", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("published_by", sa.String(255), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(63), nullable=False),
        sa.CheckConstraint("agent_type IN ('moat', 'clutter')", name="ck_security_policies_type"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_security_policies_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id", "agent_type", "version", name="uq_security_policies_tenant_version"
        ),
    )
    op.create_index(
        "ix_security_policy_versions_tenant_id", "security_policy_versions", ["tenant_id"]
    )
    op.create_index(
        "ix_security_policies_tenant_agent_published",
        "security_policy_versions",
        ["tenant_id", "agent_type", "published_at"],
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("source_event_id", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("policy_version", sa.String(64)),
        sa.Column("subject_pseudonym", sa.String(128)),
        sa.Column("target_indicator", sa.String(255)),
        sa.Column(
            "evidence", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False
        ),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(63), nullable=False),
        sa.CheckConstraint(
            "action IN ('blocked', 'warned', 'quarantined', 'allowed_override')",
            name="ck_security_events_action",
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(
            ["tenant_id", "agent_id"],
            ["security_agents.tenant_id", "security_agents.id"],
            name="fk_security_events_tenant_agent_id_agents",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_security_events_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id", "agent_id", "source_event_id", name="uq_security_events_agent_event"
        ),
    )
    op.create_index("ix_security_events_tenant_id", "security_events", ["tenant_id"])
    op.create_index(
        "ix_security_events_tenant_occurred",
        "security_events",
        ["tenant_id", "occurred_at", "id"],
    )
    op.create_index(
        "ix_security_events_tenant_severity_occurred",
        "security_events",
        ["tenant_id", "severity", "occurred_at"],
    )

    op.execute(
        """CREATE FUNCTION athena_prevent_security_evidence_mutation() RETURNS trigger AS $$
        BEGIN RAISE EXCEPTION 'security evidence is append-only'; END; $$ LANGUAGE plpgsql"""
    )
    for table in SCOPED_TABLES:
        op.execute(
            f'CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON "{table}" '
            "FOR EACH ROW EXECUTE FUNCTION athena_prevent_security_evidence_mutation()"
        )
        op.execute(f'GRANT SELECT, INSERT ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            f"TO athena_app USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )


def downgrade() -> None:
    for table in reversed(SCOPED_TABLES):
        op.execute(f'DROP POLICY IF EXISTS "{table}_tenant_isolation" ON "{table}"')
        op.execute(f'DROP TRIGGER IF EXISTS {table}_immutable ON "{table}"')
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_security_evidence_mutation()")
    op.drop_table("security_events")
    op.drop_table("security_policy_versions")
    op.drop_table("security_agents")
