"""Add GitHub connector checkpoints and grant source evidence.

Revision ID: 20260816_08
Revises: 20260816_07
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260816_08"
down_revision = "20260816_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    jsonb = postgresql.JSONB(astext_type=sa.Text())
    op.add_column(
        "access_grants",
        sa.Column("source_metadata", jsonb, server_default=sa.text("'{}'::jsonb"), nullable=False),
    )
    op.create_table(
        "connector_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("connector", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("endpoint_cache", jsonb, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector", "scope", name="uq_connector_checkpoint"),
    )


def downgrade() -> None:
    op.drop_table("connector_checkpoints")
    op.drop_column("access_grants", "source_metadata")
