"""Separate runtime login authority and enforce evidence least privilege.

Revision ID: 20260824_13
Revises: 20260823_12
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260824_13"
down_revision: str | None = "20260823_12"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

IMMUTABLE_EVIDENCE_TABLES = (
    "access_observations",
    "anomaly_model_runs",
    "anomaly_results",
    "audit_events",
    "monitoring_runs",
    "monitoring_steps",
    "policy_evaluations",
    "provenance_edges",
    "remediation_execution_events",
    "review_events",
    "risk_assessments",
    "risk_findings",
    "role_transitions",
)


def upgrade() -> None:
    op.execute(
        "ALTER ROLE athena_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
    )
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format('REVOKE athena_app FROM %I', session_user);
        END
        $$
        """
    )
    for table in IMMUTABLE_EVIDENCE_TABLES:
        op.execute(f'REVOKE UPDATE, DELETE ON "{table}" FROM athena_app')


def downgrade() -> None:
    for table in IMMUTABLE_EVIDENCE_TABLES:
        op.execute(f'GRANT UPDATE, DELETE ON "{table}" TO athena_app')
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format('GRANT athena_app TO %I', session_user);
        END
        $$
        """
    )
    op.execute("ALTER ROLE athena_app NOLOGIN")
