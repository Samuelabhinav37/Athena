import os
import uuid

import pytest
from athena.config import get_settings
from athena.database import get_session_factory
from athena.tenant_transition import TENANT_TABLES
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

pytestmark = pytest.mark.skipif(
    os.getenv("ATHENA_RUN_LOCAL_DB_TESTS") != "1",
    reason="ATHENA_RUN_LOCAL_DB_TESTS=1 is required for local PostgreSQL constraint tests",
)


def test_postgres_rejects_missing_and_cross_tenant_relationships() -> None:
    engine = create_engine(get_settings().database_url)

    with engine.connect() as connection:
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

    with engine.connect() as connection:
        transaction = connection.begin()
        other_tenant = f"constraint-test-{uuid.uuid4()}"
        group_id = uuid.uuid4()
        connection.execute(
            text(
                """
                INSERT INTO tenants (
                    id, display_name, approval_reference, authorized_by, approved_at,
                    inventory_sha256, created_at, updated_at
                ) VALUES (
                    :id, 'Constraint test', 'TEST-CONSTRAINT-2026', 'test-suite', now(),
                    :digest, now(), now()
                )
                """
            ),
            {"id": other_tenant, "digest": "0" * 64},
        )
        connection.execute(
            text(
                """
                INSERT INTO groups (
                    id, tenant_id, source, external_id, name, path, source_metadata,
                    created_at, updated_at
                ) VALUES (
                    :id, :tenant_id, 'test', :external_id, 'Other tenant', '/other',
                    '{}'::jsonb, now(), now()
                )
                """
            ),
            {"id": group_id, "tenant_id": other_tenant, "external_id": str(uuid.uuid4())},
        )
        identity_id = connection.scalar(
            text("SELECT id FROM identities WHERE tenant_id = 'athena-local' LIMIT 1")
        )
        assert identity_id is not None
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO identity_groups (tenant_id, identity_id, group_id)
                    VALUES ('athena-local', :identity_id, :group_id)
                    """
                ),
                {"identity_id": identity_id, "group_id": group_id},
            )
        transaction.rollback()

    engine.dispose()


def test_rls_is_forced_fail_closed_and_bound_to_application_role() -> None:
    engine = create_engine(get_settings().database_url)

    with engine.connect() as connection:
        role = connection.execute(
            text(
                """
                SELECT rolsuper, rolbypassrls
                FROM pg_roles
                WHERE rolname = 'athena_app'
                """
            )
        ).one()
        assert role == (False, False)
        policy_count = connection.scalar(
            text(
                """
                SELECT count(*)
                FROM pg_policies
                WHERE policyname LIKE '%_tenant_isolation'
                  AND roles = ARRAY['athena_app']::name[]
                """
            )
        )
        forced_count = connection.scalar(
            text(
                """
                SELECT count(*)
                FROM pg_class
                WHERE relname = ANY(:tables)
                  AND relrowsecurity
                  AND relforcerowsecurity
                """
            ),
            {"tables": list(TENANT_TABLES)},
        )
        assert policy_count == 25
        assert forced_count == 25

    with engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(text("SET ROLE athena_app"))
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 0
        connection.execute(text("SELECT set_config('athena.tenant_id', 'athena-local', true)"))
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 7
        connection.execute(text("SELECT set_config('athena.tenant_id', '', true)"))
        assert connection.scalar(text("SELECT count(*) FROM identities")) == 0
        transaction.rollback()

    with engine.connect() as connection:
        transaction = connection.begin()
        connection.execute(text("SET ROLE athena_app"))
        with pytest.raises(DBAPIError, match="row-level security policy"):
            connection.execute(
                text(
                    """
                    INSERT INTO groups (
                        id, tenant_id, source, external_id, name, path, source_metadata,
                        created_at, updated_at
                    ) VALUES (
                        :id, 'athena-local', 'test', :external_id, 'No context', '/no-context',
                        '{}'::jsonb, now(), now()
                    )
                    """
                ),
                {"id": uuid.uuid4(), "external_id": str(uuid.uuid4())},
            )
        transaction.rollback()

    engine.dispose()


def test_transaction_tenant_context_resets_across_pooled_sessions() -> None:
    local_factory = get_session_factory("athena-local")
    with local_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 7
        session.commit()

    unscoped_factory = get_session_factory()
    with unscoped_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0
        session.commit()

    other_factory = get_session_factory("other-tenant")
    with other_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0
        session.commit()

    with unscoped_factory() as session:
        assert session.scalar(text("SELECT count(*) FROM identities")) == 0
