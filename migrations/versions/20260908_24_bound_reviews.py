"""Add reviewer bindings and versioned exact-target reviews without rewriting history."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260908_24"
down_revision = "20260828_23"
branch_labels = None
depends_on = None
SCOPED_TABLES = ("reviewers",)
TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"


def upgrade() -> None:
    op.create_table(
        "reviewers",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(63), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provenance", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("tenant_id", "id", name="uq_reviewers_tenant_id"),
        sa.UniqueConstraint("tenant_id", "issuer", "subject", name="uq_reviewers_principal"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "identity_id"],
            ["identities.tenant_id", "identities.id"],
            name="fk_reviewers_identity",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_reviewers_tenant_id", "reviewers", ["tenant_id"])
    op.add_column("review_cases", sa.Column("owner_id", sa.Uuid()))
    op.add_column("review_cases", sa.Column("policy_evaluation_id", sa.Uuid()))
    op.add_column(
        "review_cases", sa.Column("revision", sa.Integer(), nullable=False, server_default="1")
    )
    op.add_column("review_cases", sa.Column("target_key", sa.String(64)))
    op.add_column("review_cases", sa.Column("target_snapshot", postgresql.JSONB()))
    for column, table, name in (
        ("owner_id", "reviewers", "fk_review_cases_owner"),
        ("policy_evaluation_id", "policy_evaluations", "fk_review_cases_policy"),
    ):
        op.create_foreign_key(
            name,
            "review_cases",
            table,
            ["tenant_id", column],
            ["tenant_id", "id"],
            ondelete="RESTRICT",
        )
    op.drop_constraint("ck_review_case_has_evidence", "review_cases", type_="check")
    op.create_check_constraint(
        "ck_review_case_has_evidence",
        "review_cases",
        "risk_assessment_id IS NOT NULL OR anomaly_result_id IS NOT NULL "
        "OR policy_evaluation_id IS NOT NULL",
    )
    op.create_index(
        "uq_review_cases_active_target",
        "review_cases",
        ["tenant_id", "target_key"],
        unique=True,
        postgresql_where=sa.text("target_key IS NOT NULL AND status IN ('open', 'in_review')"),
    )
    for table in SCOPED_TABLES:
        op.execute(f'GRANT SELECT, INSERT ON "{table}" TO athena_app')
        op.execute(f'GRANT UPDATE (active) ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            f"TO athena_app USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )
    op.execute("""CREATE FUNCTION athena_guard_reviewer_binding() RETURNS trigger AS $$
    BEGIN
      IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
         OR NEW.issuer IS DISTINCT FROM OLD.issuer
         OR NEW.subject IS DISTINCT FROM OLD.subject
         OR NEW.provenance IS DISTINCT FROM OLD.provenance
         OR NEW.identity_id IS DISTINCT FROM OLD.identity_id THEN
        RAISE EXCEPTION 'reviewer bindings are immutable';
      END IF;
      RETURN NEW;
    END; $$ LANGUAGE plpgsql""")
    op.execute(
        "CREATE TRIGGER reviewers_binding_immutable BEFORE UPDATE ON reviewers "
        "FOR EACH ROW EXECUTE FUNCTION athena_guard_reviewer_binding()"
    )
    op.execute("""CREATE FUNCTION athena_guard_review_target() RETURNS trigger AS $$
    BEGIN
      IF NEW.target_key IS DISTINCT FROM OLD.target_key
         OR NEW.target_snapshot IS DISTINCT FROM OLD.target_snapshot
         OR NEW.policy_evaluation_id IS DISTINCT FROM OLD.policy_evaluation_id
         OR (OLD.target_snapshot IS NOT NULL AND (
            NEW.identity_id IS DISTINCT FROM OLD.identity_id
            OR NEW.entitlement_id IS DISTINCT FROM OLD.entitlement_id
            OR NEW.risk_assessment_id IS DISTINCT FROM OLD.risk_assessment_id
            OR NEW.anomaly_result_id IS DISTINCT FROM OLD.anomaly_result_id)) THEN
        RAISE EXCEPTION 'review target evidence is immutable';
      END IF;
      RETURN NEW;
    END; $$ LANGUAGE plpgsql""")
    op.execute(
        "CREATE TRIGGER review_target_immutable BEFORE UPDATE ON review_cases "
        "FOR EACH ROW EXECUTE FUNCTION athena_guard_review_target()"
    )


def downgrade() -> None:
    raise RuntimeError("Review ownership migration is forward-only; preserve review evidence")
