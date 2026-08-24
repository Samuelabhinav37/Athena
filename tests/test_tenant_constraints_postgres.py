import os
import uuid
from collections.abc import Iterator

import pytest
from athena.config import get_settings
from athena.database import get_engine, get_session_factory
from athena.tenant_transition import IMMUTABLE_EVIDENCE_TABLES, TENANT_TABLES
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

pytestmark = pytest.mark.skipif(
    not os.getenv("ATHENA_TEST_DATABASE_URL"),
    reason="ATHENA_TEST_DATABASE_URL is required for disposable PostgreSQL tests",
)

TEST_SUFFIX = uuid.uuid4().hex
TENANT_A = f"test-a-{TEST_SUFFIX}"
TENANT_B = f"test-b-{TEST_SUFFIX}"


@pytest.fixture(scope="module")
def postgres_engines() -> Iterator[tuple[Engine, Engine, uuid.UUID, uuid.UUID]]:
    owner_engine = create_engine(os.environ["ATHENA_TEST_DATABASE_URL"])
    app_engine = create_engine(get_settings().database_url)
    identity_id = uuid.uuid4()
    group_id = uuid.uuid4()
    with owner_engine.begin() as connection:
        for tenant_id in (TENANT_A, TENANT_B):
            connection.execute(
                text(
                    """
                    INSERT INTO tenants (
                        id, display_name, approval_reference, authorized_by, approved_at,
                        inventory_sha256, created_at, updated_at
                    ) VALUES (
                        :id, :id, 'DISPOSABLE-TEST-2026', 'test-suite', now(),
                        :digest, now(), now()
                    )
                    """
                ),
                {"id": tenant_id, "digest": "0" * 64},
            )
        connection.execute(
            text(
                """
                INSERT INTO identities (
                    id, tenant_id, source, external_id, username, identity_type,
                    display_name, active, source_metadata, observed_at, created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'tenant-a-user', 'human',
                    'Tenant A User', true, '{}'::jsonb, now(), now(), now()
                )
                """
            ),
            {"id": identity_id, "tenant_id": TENANT_A, "external_id": TEST_SUFFIX},
        )
        connection.execute(
            text(
                """
                INSERT INTO groups (
                    id, tenant_id, source, external_id, name, path, source_metadata,
                    created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'Tenant B Group', '/tenant-b',
                    '{}'::jsonb, now(), now()
                )
                """
            ),
            {"id": group_id, "tenant_id": TENANT_B, "external_id": TEST_SUFFIX},
        )
    yield owner_engine, app_engine, identity_id, group_id
    owner_engine.dispose()
    app_engine.dispose()


def test_postgres_rejects_missing_and_cross_tenant_relationships(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    owner_engine, _, identity_id, group_id = postgres_engines
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO groups (
                        id, source, external_id, name, path, source_metadata,
                        created_at, updated_at
                    ) VALUES (
                        :id, 'test', :external_id, 'Missing tenant', '/missing',
                        '{}'::jsonb, now(), now()
                    )
                    """
                ),
                {"id": uuid.uuid4(), "external_id": str(uuid.uuid4())},
            )
        transaction.rollback()

    with owner_engine.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO identity_groups (tenant_id, identity_id, group_id)
                    VALUES (:tenant_id, :identity_id, :group_id)
                    """
                ),
                {"tenant_id": TENANT_A, "identity_id": identity_id, "group_id": group_id},
            )
        transaction.rollback()


def test_postgres_restricts_deleting_access_grant_requester_and_approver(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    owner_engine, _, _, group_id = postgres_engines
    actor_id = uuid.uuid4()
    resource_id = uuid.uuid4()
    permission_id = uuid.uuid4()
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(
            text(
                """
                INSERT INTO identities (
                    id, tenant_id, source, external_id, username, identity_type,
                    display_name, active, source_metadata, observed_at, created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'grant-actor', 'human',
                    'Grant Actor', true, '{}'::jsonb, now(), now(), now()
                )
                """
            ),
            {"id": actor_id, "tenant_id": TENANT_B, "external_id": str(actor_id)},
        )
        connection.execute(
            text(
                """
                INSERT INTO resources (
                    id, tenant_id, source, external_id, resource_type, name,
                    source_metadata, created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'repository', 'Grant resource',
                    '{}'::jsonb, now(), now()
                )
                """
            ),
            {"id": resource_id, "tenant_id": TENANT_B, "external_id": str(resource_id)},
        )
        connection.execute(
            text(
                """
                INSERT INTO permissions (
                    id, tenant_id, resource_id, action, effect, conditions,
                    created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, :resource_id, 'read', 'allow', '{}'::jsonb,
                    now(), now()
                )
                """
            ),
            {"id": permission_id, "tenant_id": TENANT_B, "resource_id": resource_id},
        )
        connection.execute(
            text(
                """
                INSERT INTO access_grants (
                    id, tenant_id, source, external_id, subject_type, group_id,
                    permission_id, requested_by_identity_id, approved_by_identity_id,
                    granted_at, source_metadata, created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'group', :group_id,
                    :permission_id, :actor_id, :actor_id, now(), '{}'::jsonb, now(), now()
                )
                """
            ),
            {
                "id": uuid.uuid4(),
                "tenant_id": TENANT_B,
                "external_id": str(uuid.uuid4()),
                "group_id": group_id,
                "permission_id": permission_id,
                "actor_id": actor_id,
            },
        )

        with pytest.raises(IntegrityError):
            connection.execute(text("DELETE FROM identities WHERE id = :id"), {"id": actor_id})
        transaction.rollback()

def test_rls_is_forced_fail_closed_for_direct_application_login(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    owner_engine, app_engine, _, _ = postgres_engines
    with owner_engine.connect() as connection:
        role = connection.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname='athena_app'"
            )
        ).one()
        assert role == (True, False, False)
        assert (
            connection.scalar(
                text(
                    """
                SELECT count(*) FROM pg_policies
                WHERE policyname LIKE '%_tenant_isolation'
                  AND roles = ARRAY['athena_app']::name[]
                """
                )
            )
            == 25
        )
        assert (
            connection.scalar(
                text(
                    """
                SELECT count(*) FROM pg_class
                WHERE relname = ANY(:tables) AND relrowsecurity AND relforcerowsecurity
                """
                ),
                {"tables": list(TENANT_TABLES)},
            )
            == 25
        )

    with app_engine.connect() as connection:
        transaction = connection.begin()
        assert connection.execute(text("SELECT current_user, session_user")).one() == (
            "athena_app",
            "athena_app",
        )
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 0
        connection.execute(
            text("SELECT set_config('athena.tenant_id', :tenant_id, true)"),
            {"tenant_id": TENANT_A},
        )
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 1
        connection.execute(text("SELECT set_config('athena.tenant_id', '', true)"))
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 0
        transaction.rollback()

    with app_engine.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(DBAPIError, match="row-level security policy"):
            connection.execute(
                text(
                    """
                    INSERT INTO groups (
                        id, tenant_id, source, external_id, name, path, source_metadata,
                        created_at, updated_at
                    ) VALUES (
                        :id, :tenant_id, 'test', :external_id, 'No context', '/no-context',
                        '{}'::jsonb, now(), now()
                    )
                    """
                ),
                {
                    "id": uuid.uuid4(),
                    "tenant_id": TENANT_A,
                    "external_id": str(uuid.uuid4()),
                },
            )
        transaction.rollback()


def test_transaction_tenant_context_resets_across_pooled_sessions(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    _ = postgres_engines
    local_factory = get_session_factory(TENANT_A)
    with local_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 1
        session.commit()

    unscoped_factory = get_session_factory()
    with unscoped_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0
        session.commit()

    other_factory = get_session_factory(TENANT_B)
    with other_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0
        session.commit()

    with unscoped_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0


def test_runtime_login_cannot_recover_schema_owner(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    _ = postgres_engines
    engine = get_engine()
    with engine.connect() as connection:
        assert connection.execute(text("SELECT current_user, session_user")).one() == (
            "athena_app",
            "athena_app",
        )
        with pytest.raises(DBAPIError):
            connection.execute(text("SET ROLE athena"))


def test_runtime_role_has_insert_only_mutation_access_to_immutable_evidence(
    postgres_engines: tuple[Engine, Engine, uuid.UUID, uuid.UUID],
) -> None:
    owner_engine, _, _, _ = postgres_engines
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT table_name, privilege_type
                FROM information_schema.role_table_grants
                WHERE grantee = 'athena_app' AND table_name = ANY(:tables)
                """
            ),
            {"tables": list(IMMUTABLE_EVIDENCE_TABLES)},
        )
        privileges: dict[str, set[str]] = {table: set() for table in IMMUTABLE_EVIDENCE_TABLES}
        for table, privilege in rows:
            privileges[table].add(privilege)

        assert all(grants == {"INSERT", "SELECT"} for grants in privileges.values())
