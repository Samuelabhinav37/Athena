"""Create authorization provenance and append-only audit tables.

Revision ID: 20260816_02
Revises: 20260816_01
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260816_02"
down_revision: str | None = "20260816_01"
branch_labels: str | None = None
depends_on: str | None = None


def timestamp_columns() -> list[sa.Column]:
    return [
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
    ]


def upgrade() -> None:
    metadata_type = postgresql.JSONB(astext_type=sa.Text())
    resource_type = sa.Enum(
        "application",
        "database",
        "cloud",
        "repository",
        "kubernetes",
        "data",
        "other",
        name="resource_type",
        native_enum=False,
    )
    sensitivity = sa.Enum(
        "low",
        "moderate",
        "high",
        "critical",
        name="resource_sensitivity",
        native_enum=False,
    )
    subject_type = sa.Enum(
        "identity",
        "group",
        "role",
        name="grant_subject_type",
        native_enum=False,
    )

    op.create_table(
        "resources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("resource_type", resource_type, nullable=False),
        sa.Column("sensitivity", sensitivity, nullable=False),
        sa.Column("source_metadata", metadata_type, nullable=False),
        *timestamp_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_resource_source_external"),
    )
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("privileged", sa.Boolean(), nullable=False),
        *timestamp_columns(),
        sa.ForeignKeyConstraint(["resource_id"], ["resources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("resource_id", "action", name="uq_permission_resource_action"),
    )
    op.create_table(
        "access_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("subject_type", subject_type, nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=True),
        sa.Column("group_id", sa.Uuid(), nullable=True),
        sa.Column("role_id", sa.Uuid(), nullable=True),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_identity_id", sa.Uuid(), nullable=True),
        sa.Column("approved_by_identity_id", sa.Uuid(), nullable=True),
        sa.Column("business_reason", sa.Text(), nullable=True),
        sa.Column("policy_reference", sa.String(length=255), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *timestamp_columns(),
        sa.CheckConstraint(
            "(CASE WHEN identity_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN group_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN role_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_access_grants_exactly_one_subject",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_identity_id"], ["identities.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["permission_id"], ["permissions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["requested_by_identity_id"], ["identities.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_access_grant_source_external"),
    )
    op.create_table(
        "effective_entitlements",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.Column("grant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["grant_id"], ["access_grants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["permission_id"], ["permissions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("identity_id", "grant_id", name="uq_entitlement_identity_grant"),
    )
    op.create_index(
        op.f("ix_effective_entitlements_identity_id"),
        "effective_entitlements",
        ["identity_id"],
    )
    op.create_table(
        "provenance_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("entitlement_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_type", sa.String(length=64), nullable=False),
        sa.Column("from_id", sa.Uuid(), nullable=False),
        sa.Column("from_label", sa.String(length=255), nullable=False),
        sa.Column("relationship", sa.String(length=64), nullable=False),
        sa.Column("to_type", sa.String(length=64), nullable=False),
        sa.Column("to_id", sa.Uuid(), nullable=False),
        sa.Column("to_label", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ["entitlement_id"], ["effective_entitlements.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entitlement_id", "sequence", name="uq_provenance_edge_sequence"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("actor_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=False),
        sa.Column("old_state", metadata_type, nullable=True),
        sa.Column("new_state", metadata_type, nullable=True),
        sa.Column("policy_reference", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("approval", metadata_type, nullable=True),
        sa.Column("risk_before", sa.Float(), nullable=True),
        sa.Column("risk_after", sa.Float(), nullable=True),
        sa.Column("model_version", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_events_occurred_at"), "audit_events", ["occurred_at"])
    op.execute(
        """
        CREATE FUNCTION athena_prevent_audit_event_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION athena_prevent_audit_event_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
    op.execute("DROP FUNCTION IF EXISTS athena_prevent_audit_event_mutation()")
    op.drop_index(op.f("ix_audit_events_occurred_at"), table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("provenance_edges")
    op.drop_index(
        op.f("ix_effective_entitlements_identity_id"), table_name="effective_entitlements"
    )
    op.drop_table("effective_entitlements")
    op.drop_table("access_grants")
    op.drop_table("permissions")
    op.drop_table("resources")
