"""Run only against the explicitly configured disposable PostgreSQL database."""

import os
import uuid

import pytest
from athena.config import get_settings
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

pytestmark = pytest.mark.skipif(
    not os.getenv("ATHENA_TEST_DATABASE_URL"),
    reason="ATHENA_TEST_DATABASE_URL is required for disposable PostgreSQL tests",
)


@pytest.fixture(scope="module")
def link_database():
    owner_url = make_url(os.environ["ATHENA_TEST_DATABASE_URL"])
    runtime_url = make_url(get_settings().database_url)
    if any(url.get_backend_name() != "postgresql" for url in (owner_url, runtime_url)):
        pytest.fail("Person-link integration tests require PostgreSQL")
    if (owner_url.host, owner_url.port, owner_url.database) != (
        runtime_url.host, runtime_url.port, runtime_url.database
    ):
        pytest.fail("Owner and runtime must target the same disposable database")
    if runtime_url.username != "athena_app" or owner_url.username == runtime_url.username:
        pytest.fail("Use a separate owner and the restricted athena_app runtime role")
    owner = create_engine(owner_url)
    runtime = create_engine(runtime_url)
    tenant = f"link-test-{uuid.uuid4().hex}"
    anchor, account, person, link, event = (uuid.uuid4() for _ in range(5))
    with owner.begin() as connection:
        connection.execute(
            text("""INSERT INTO tenants
            (id, display_name, approval_reference, authorized_by, approved_at,
             inventory_sha256, created_at, updated_at)
            VALUES (:tenant, :tenant, 'disposable-test', 'test-suite', now(), :digest, now(), now())
        """),
            {"tenant": tenant, "digest": "0" * 64},
        )
        connection.execute(
            text("""INSERT INTO identities
            (id, tenant_id, source, external_id, username, identity_type,
             display_name, active, source_metadata, observed_at, created_at, updated_at)
            VALUES (:id, :tenant, 'keycloak', :external_id, :external_id, 'human',
                    'Synthetic account', true, '{}'::jsonb, now(), now(), now())
        """),
            [
                {"id": identifier, "external_id": str(identifier), "tenant": tenant}
                for identifier in (anchor, account)
            ],
        )
        connection.execute(
            text("""INSERT INTO persons
            (id, tenant_id, identity_id, issuer, subject, created_at)
            VALUES (:id, :tenant, :anchor, 'https://synthetic.test', 'synthetic-subject', now())
        """),
            {"id": person, "tenant": tenant, "anchor": anchor},
        )
        connection.execute(
            text("""INSERT INTO person_links
            (id, tenant_id, person_id, account_id, status, revision, snapshot,
             created_at, expires_at)
            VALUES (:id, :tenant, :person, :account, 'proposed', 1, '{}'::jsonb,
                    now(), now() + interval '30 days')
        """),
            {"id": link, "tenant": tenant, "person": person, "account": account},
        )
        connection.execute(
            text("""INSERT INTO person_link_events
            (id, tenant_id, link_id, revision, action, actor, reason, occurred_at)
            VALUES (:id, :tenant, :link, 1, 'proposed', '{}'::jsonb, 'Synthetic evidence', now())
        """),
            {"id": event, "tenant": tenant, "link": link},
        )
    try:
        yield owner, runtime, tenant, person, link, event
    finally:
        runtime.dispose()
        owner.dispose()


def scope(connection, tenant):
    connection.execute(
        text("SELECT set_config('athena.tenant_id', :tenant, true)"), {"tenant": tenant}
    )


@pytest.mark.parametrize("context", ["", "unrelated-tenant", "own"])
def test_runtime_link_visibility_requires_matching_tenant(link_database, context):
    _, runtime, tenant, person, link, event = link_database
    with runtime.connect() as connection:
        scope(connection, tenant if context == "own" else context)
        for table, identifier in (
            ("persons", person),
            ("person_links", link),
            ("person_link_events", event),
        ):
            count = connection.scalar(
                text(f"SELECT count(*) FROM {table} WHERE id = :id"), {"id": identifier}
            )
            assert count == (1 if context == "own" else 0)


@pytest.mark.parametrize("login", ["runtime", "owner"])
def test_person_evidence_and_target_updates_are_rejected_by_database(link_database, login):
    owner, runtime, tenant, person, link, event = link_database
    engine = runtime if login == "runtime" else owner
    for statement, identifier in (
        ("UPDATE persons SET subject = 'changed' WHERE id = :id", person),
        ("DELETE FROM persons WHERE id = :id", person),
        ("UPDATE person_link_events SET reason = 'changed' WHERE id = :id", event),
        ("DELETE FROM person_link_events WHERE id = :id", event),
        ("UPDATE person_links SET snapshot = '{\"changed\":true}'::jsonb WHERE id = :id", link),
        ("DELETE FROM person_links WHERE id = :id", link),
    ):
        with engine.connect() as connection:
            scope(connection, tenant)
            with pytest.raises(DBAPIError) as caught:
                connection.execute(text(statement), {"id": identifier})
            assert caught.value.orig.sqlstate == ("42501" if login == "runtime" else "P0001")
            connection.rollback()


def test_runtime_can_update_only_link_projection_columns(link_database):
    _, runtime, tenant, _, link, _ = link_database
    with runtime.connect() as connection:
        scope(connection, tenant)
        assert (
            connection.execute(
                text("""UPDATE person_links SET status='confirmed', revision=2
            WHERE id=:id AND revision=1"""),
                {"id": link},
            ).rowcount
            == 1
        )
        assert (
            connection.scalar(
                text("SELECT count(*) FROM person_link_events WHERE link_id=:id"), {"id": link}
            )
            == 1
        )
        connection.rollback()


def test_postgres_rejects_duplicate_current_link(link_database):
    owner, _, _, _, link, _ = link_database
    with owner.connect() as connection:
        with pytest.raises(IntegrityError) as caught:
            connection.execute(
                text("""INSERT INTO person_links
                (id, tenant_id, person_id, account_id, status, revision, snapshot,
                 created_at, expires_at)
                SELECT :new_id, tenant_id, person_id, account_id, status, revision, snapshot,
                       created_at, expires_at FROM person_links WHERE id=:id
            """),
                {"new_id": uuid.uuid4(), "id": link},
            )
        assert caught.value.orig.sqlstate == "23505"
        assert caught.value.orig.diag.constraint_name == "uq_person_links_current_account"
        connection.rollback()


def test_postgres_link_row_lock_excludes_concurrent_confirmation(link_database):
    _, runtime, tenant, _, link, _ = link_database
    with runtime.connect() as first, runtime.connect() as second:
        scope(first, tenant)
        scope(second, tenant)
        first.execute(text("SELECT id FROM person_links WHERE id=:id FOR UPDATE"), {"id": link})
        with pytest.raises(DBAPIError) as caught:
            second.execute(
                text("SELECT id FROM person_links WHERE id=:id FOR UPDATE NOWAIT"), {"id": link}
            )
        assert caught.value.orig.sqlstate == "55P03"
        second.rollback()
        first.rollback()
