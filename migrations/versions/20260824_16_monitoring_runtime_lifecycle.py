"""Permit runtime monitoring lifecycle transitions without mutable step evidence.

Revision ID: 20260824_16
Revises: 20260824_15
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260824_16"
down_revision: str | None = "20260824_15"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LIFECYCLE_COLUMNS = (
    "status",
    "attempt_count",
    "started_at",
    "completed_at",
    "error",
    "summary",
)


def upgrade() -> None:
    columns = ", ".join(f'"{column}"' for column in LIFECYCLE_COLUMNS)
    op.execute(f'GRANT UPDATE ({columns}) ON "monitoring_runs" TO athena_app')


def downgrade() -> None:
    columns = ", ".join(f'"{column}"' for column in LIFECYCLE_COLUMNS)
    op.execute(f'REVOKE UPDATE ({columns}) ON "monitoring_runs" FROM athena_app')
