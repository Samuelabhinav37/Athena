"""Add recoverable monitoring leases and heartbeat coordination.

Revision ID: 20260824_18
Revises: 20260824_17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260824_18"
down_revision: str | None = "20260824_17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LEASE_COLUMNS = ("lease_token", "heartbeat_at", "lease_expires_at")


def upgrade() -> None:
    op.add_column("monitoring_runs", sa.Column("lease_token", sa.Uuid(), nullable=True))
    op.add_column(
        "monitoring_runs",
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "monitoring_runs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    columns = ", ".join(f'"{column}"' for column in LEASE_COLUMNS)
    op.execute(f'GRANT UPDATE ({columns}) ON "monitoring_runs" TO athena_app')


def downgrade() -> None:
    columns = ", ".join(f'"{column}"' for column in LEASE_COLUMNS)
    op.execute(f'REVOKE UPDATE ({columns}) ON "monitoring_runs" FROM athena_app')
    op.drop_column("monitoring_runs", "lease_expires_at")
    op.drop_column("monitoring_runs", "heartbeat_at")
    op.drop_column("monitoring_runs", "lease_token")
