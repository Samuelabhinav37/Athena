"""Add pilot person anchors and versioned two-steward link evidence."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260909_25"
down_revision = "20260908_24"
branch_labels = None
depends_on = None
SCOPED_TABLES = ("persons", "person_links", "person_link_events")
TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"


def common(table):
    return [
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(63), sa.ForeignKey("tenants.id"), nullable=False),
        sa.UniqueConstraint("tenant_id", "id", name=f"uq_{table}_tenant_id"),
    ]


def fk(column, parent, name):
    return sa.ForeignKeyConstraint(
        ["tenant_id", column],
        [f"{parent}.tenant_id", f"{parent}.id"],
        name=name,
        ondelete="RESTRICT",
    )


def upgrade():
    op.create_table(
        "persons",
        *common("persons"),
        sa.Column("identity_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "identity_id", name="uq_persons_anchor"),
        fk("identity_id", "identities", "fk_persons_anchor"),
    )
    op.create_table(
        "person_links",
        *common("person_links"),
        sa.Column("person_id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        fk("person_id", "persons", "fk_person_links_person"),
        fk("account_id", "identities", "fk_person_links_account"),
        sa.CheckConstraint(
            "status IN ('proposed', 'confirmed', 'rejected', 'revoked')",
            name="ck_person_links_status",
        ),
    )
    op.create_index(
        "uq_person_links_current_account",
        "person_links",
        ["tenant_id", "account_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('proposed', 'confirmed')"),
    )
    op.create_table(
        "person_link_events",
        *common("person_link_events"),
        sa.Column("link_id", sa.Uuid(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("actor", postgresql.JSONB(), nullable=False),
        sa.Column("reason", sa.String(2000), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "link_id", "revision", name="uq_person_link_events_revision"
        ),
        fk("link_id", "person_links", "fk_person_link_events_link"),
    )
    for table in SCOPED_TABLES:
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
        op.execute(f'GRANT SELECT, INSERT ON "{table}" TO athena_app')
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(
            f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
            f"TO athena_app USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})"
        )
    op.execute("GRANT UPDATE (status, revision) ON person_links TO athena_app")
    op.execute("""CREATE FUNCTION athena_guard_person_evidence() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'person anchors and link events are immutable';
    END; $$ LANGUAGE plpgsql""")
    for table in ("persons", "person_link_events"):
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION athena_guard_person_evidence()"
        )
    op.execute("""CREATE FUNCTION athena_guard_person_link() RETURNS trigger AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'person links cannot be deleted'; END IF;
      IF (to_jsonb(NEW) - 'status' - 'revision') IS DISTINCT FROM
         (to_jsonb(OLD) - 'status' - 'revision') THEN
        RAISE EXCEPTION 'person link targets are immutable';
      END IF;
      RETURN NEW;
    END; $$ LANGUAGE plpgsql""")
    op.execute(
        "CREATE TRIGGER person_links_immutable BEFORE UPDATE OR DELETE ON person_links "
        "FOR EACH ROW EXECUTE FUNCTION athena_guard_person_link()"
    )


def downgrade():
    raise RuntimeError("Person-link evidence is forward-only")
