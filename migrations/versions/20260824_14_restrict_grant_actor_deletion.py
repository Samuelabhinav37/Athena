"""Preserve access-grant requester and approver identity references.

Revision ID: 20260824_14
Revises: 20260824_13
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260824_14"
down_revision: str | None = "20260824_13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ACTOR_FOREIGN_KEYS = (
    (
        "fk_access_grants_tenant_requested_by_identity_id_identities",
        "requested_by_identity_id",
    ),
    (
        "fk_access_grants_tenant_approved_by_identity_id_identities",
        "approved_by_identity_id",
    ),
)


def _replace_actor_foreign_keys(ondelete: str) -> None:
    for name, column in ACTOR_FOREIGN_KEYS:
        op.drop_constraint(name, "access_grants", type_="foreignkey")
        op.create_foreign_key(
            name,
            "access_grants",
            "identities",
            ["tenant_id", column],
            ["tenant_id", "id"],
            ondelete=ondelete,
        )


def upgrade() -> None:
    _replace_actor_foreign_keys("RESTRICT")


def downgrade() -> None:
    _replace_actor_foreign_keys("SET NULL")
