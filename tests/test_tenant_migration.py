import ast
from pathlib import Path

from athena.models import Base
from athena.tenant_transition import (
    TENANT_TABLES,
    BootstrapTenantApproval,
    build_tenant_transition_plan,
)


def test_additive_tenant_schema_covers_every_scoped_table() -> None:
    migration = Path("migrations/versions/20260820_10_add_tenant_scope.py").read_text(
        encoding="utf-8"
    )

    assert "revision: str = \"20260820_10\"" in migration
    assert "down_revision: str | None = \"20260817_09\"" in migration
    assert set(TENANT_TABLES) == set(Base.metadata.tables) - {"tenants"}
    for table_name in TENANT_TABLES:
        assert "tenant_id" in Base.metadata.tables[table_name].columns
    assert Base.metadata.tables["tenants"].columns["id"].nullable is False


def test_rls_migration_history_covers_every_current_scoped_table() -> None:
    protected_tables: set[str] = set()
    for migration_path in Path("migrations/versions").glob("*.py"):
        source = migration_path.read_text(encoding="utf-8")
        if "CREATE POLICY" not in source:
            continue
        module = ast.parse(source)
        for statement in module.body:
            if not isinstance(statement, ast.Assign):
                continue
            if not any(
                isinstance(target, ast.Name) and target.id == "SCOPED_TABLES"
                for target in statement.targets
            ):
                continue
            protected_tables.update(ast.literal_eval(statement.value))
        assert "for table in SCOPED_TABLES:" in source
        assert (
            'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}"' in source
            or 'GRANT SELECT ON "{table}"' in source
            or 'GRANT SELECT, INSERT ON "{table}"' in source
        )
        assert 'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
        assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
        assert 'CREATE POLICY "{table}_tenant_isolation"' in source
        assert "USING ({TENANT_EXPRESSION}) WITH CHECK ({TENANT_EXPRESSION})" in source

    assert set(TENANT_TABLES) <= protected_tables


def test_first_tenant_migration_is_nullable_and_performs_no_backfill() -> None:
    migration = Path("migrations/versions/20260820_10_add_tenant_scope.py").read_text(
        encoding="utf-8"
    )
    upgrade = migration.split("def upgrade() -> None:", 1)[1].split("def downgrade()", 1)[0]

    assert 'sa.Column("tenant_id", sa.String(length=63), nullable=True)' in upgrade
    assert "op.execute" not in upgrade
    assert "UPDATE " not in upgrade.upper()
    assert "row-level" not in upgrade.lower()


def test_versioned_bootstrap_approval_is_valid_and_bound_to_plan() -> None:
    approval = BootstrapTenantApproval.model_validate_json(
        Path("tenancy/bootstrap-approval.json").read_bytes()
    )
    plan = build_tenant_transition_plan(approval)

    assert approval.tenant_id == "athena-local"
    assert approval.approval_reference == "LOCAL-BOOTSTRAP-2026-001"
    assert sum(approval.expected_preexisting_rows.values()) == 614
    assert approval.inventory_sha256.startswith("22171f")
    assert plan.bootstrap == approval
