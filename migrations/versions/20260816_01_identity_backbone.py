"""Create the canonical identity backbone.

Revision ID: 20260816_01
Revises:
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260816_01"
down_revision: str | None = None
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
    identity_type = sa.Enum(
        "human",
        "service_account",
        "application",
        "workload",
        "api_client",
        "agent",
        name="identity_type",
        native_enum=False,
        create_constraint=False,
    )

    op.create_table(
        "groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("source_metadata", metadata_type, nullable=False),
        *timestamp_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_group_source_external"),
    )
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("source_metadata", metadata_type, nullable=False),
        *timestamp_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_role_source_external"),
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("identity_type", identity_type, nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("department", sa.String(length=128), nullable=True),
        sa.Column("job_title", sa.String(length=255), nullable=True),
        sa.Column("manager_external_id", sa.String(length=255), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("source_metadata", metadata_type, nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        *timestamp_columns(),
        sa.CheckConstraint(
            "identity_type IN "
            "('human', 'service_account', 'application', 'workload', 'api_client', 'agent')",
            name="ck_identities_identity_type",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", name="uq_identity_source_external"),
    )
    op.create_index(op.f("ix_identities_department"), "identities", ["department"])
    op.create_index(op.f("ix_identities_username"), "identities", ["username"])
    op.create_table(
        "identity_groups",
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("identity_id", "group_id"),
    )
    op.create_table(
        "identity_roles",
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("identity_id", "role_id"),
    )


def downgrade() -> None:
    op.drop_table("identity_roles")
    op.drop_table("identity_groups")
    op.drop_index(op.f("ix_identities_username"), table_name="identities")
    op.drop_index(op.f("ix_identities_department"), table_name="identities")
    op.drop_table("identities")
    op.drop_table("roles")
    op.drop_table("groups")
