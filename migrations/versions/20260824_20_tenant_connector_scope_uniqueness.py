"""Scope connector binding uniqueness to each tenant.

Revision ID: 20260824_20
Revises: 20260824_19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260824_20"
down_revision: str | None = "20260824_19"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_connector_scope_bindings_connector_scope",
        "connector_scope_bindings",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_connector_scope_bindings_tenant_connector_scope",
        "connector_scope_bindings",
        ["tenant_id", "connector", "scope"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_connector_scope_bindings_tenant_connector_scope",
        "connector_scope_bindings",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_connector_scope_bindings_connector_scope",
        "connector_scope_bindings",
        ["connector", "scope"],
    )
