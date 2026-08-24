"""Install forced, fail-closed tenant row-level security.

Revision ID: 20260823_12
Revises: 20260823_11
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260823_12"
down_revision: str | None = "20260823_11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPLICATION_ROLE = "athena_app"
TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"
SCOPED_TABLES = (
    "access_grants",
    "access_observations",
    "anomaly_model_runs",
    "anomaly_results",
    "audit_events",
    "connector_checkpoints",
    "effective_entitlements",
    "groups",
    "identities",
    "identity_groups",
    "identity_roles",
    "monitoring_runs",
    "monitoring_steps",
    "permissions",
    "policy_evaluations",
    "provenance_edges",
    "remediation_execution_events",
    "remediation_executions",
    "resources",
    "review_cases",
    "review_events",
    "risk_assessments",
    "risk_findings",
    "role_transitions",
    "roles",
)


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'athena_app') THEN
                CREATE ROLE athena_app
                    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            EXECUTE format('GRANT athena_app TO %I', session_user);
        END
        $$
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO athena_app")
    op.execute("GRANT SELECT ON tenants TO athena_app")
    for table in SCOPED_TABLES:
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            f"TO athena_app USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )


def downgrade() -> None:
    for table in reversed(SCOPED_TABLES):
        op.execute(f'DROP POLICY "{table}_tenant_isolation" ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
        op.execute(f'REVOKE SELECT, INSERT, UPDATE, DELETE ON "{table}" FROM athena_app')
    op.execute("REVOKE SELECT ON tenants FROM athena_app")
    op.execute("REVOKE USAGE ON SCHEMA public FROM athena_app")
