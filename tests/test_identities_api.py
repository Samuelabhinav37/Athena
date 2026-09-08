from collections.abc import Generator

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, Group, Identity, IdentityType, Role
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def session_factory() -> Generator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Generator[TestClient]:
    def override_session() -> Generator[Session]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def alice(session_factory: sessionmaker[Session]) -> Identity:
    with session_factory.begin() as session:
        engineering = Group(
            source="keycloak",
            external_id="group-engineering",
            name="engineering",
            path="/departments/engineering",
        )
        developer = Role(
            source="keycloak",
            external_id="role-developer",
            name="developer",
            description="Application developer",
        )
        identity = Identity(
            source="keycloak",
            external_id="user-alice",
            username="alice",
            identity_type=IdentityType.HUMAN,
            display_name="Alice Johnson",
            email="alice@acme.test",
            department="engineering",
            job_title="Developer",
            manager_external_id="bob",
            groups=[engineering],
            roles=[developer],
        )
        session.add(identity)
    return identity


def test_list_identities_returns_normalized_relationships(
    client: TestClient, alice: Identity
) -> None:
    response = client.get("/v1/identities")

    assert response.status_code == 200
    payload = response.json()
    assert payload[0].pop("observed_at")
    assert payload == [
        {
            "id": str(alice.id),
            "source": "keycloak",
            "external_id": "user-alice",
            "username": "alice",
            "identity_type": "human",
            "display_name": "Alice Johnson",
            "email": "alice@acme.test",
            "department": "engineering",
            "job_title": "Developer",
            "manager_external_id": "bob",
            "active": True,
            "groups": [
                {
                    "id": str(alice.groups[0].id),
                    "name": "engineering",
                    "path": "/departments/engineering",
                }
            ],
            "roles": [
                {
                    "id": str(alice.roles[0].id),
                    "name": "developer",
                    "description": "Application developer",
                }
            ],
        }
    ]


def test_get_identity_returns_404_for_unknown_id(client: TestClient) -> None:
    response = client.get("/v1/identities/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json() == {"detail": "Identity not found"}


def test_list_identities_validates_pagination(client: TestClient) -> None:
    response = client.get("/v1/identities?limit=201")

    assert response.status_code == 422


def test_inventory_search_and_pages_cover_more_than_200_identities(
    client: TestClient, session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as session:
        session.add_all([
            Identity(source="keycloak", external_id=f"user-{index}",
                     username=f"user-{index:03}", display_name="Repeated Name",
                     email=f"user{index}@acme.test", department="Engineering",
                     identity_type=IdentityType.HUMAN)
            for index in range(205)
        ])
    pages = [client.get(f"/v1/identities/inventory?limit=50&offset={offset}")
             for offset in range(0, 250, 50)]
    assert all(page.status_code == 200 for page in pages)
    assert all(page.json()["total"] == 205 for page in pages)
    items = [item for page in pages for item in page.json()["items"]]
    assert len(items) == len({item["id"] for item in items}) == 205
    assert [item["username"] for item in items] == [f"user-{i:03}" for i in range(205)]
    found = client.get("/v1/identities/inventory", params={"q": " USER204@ACME.TEST "})
    assert found.json()["total"] == 1
    assert found.json()["items"][0]["username"] == "user-204"
    assert client.get("/v1/identities/inventory?q=engineering").json()["total"] == 205
    assert client.get("/v1/identities/inventory?q=no-match").json()["items"] == []
    empty_page = client.get("/v1/identities/inventory?offset=250").json()
    assert empty_page["total"] == 205 and empty_page["items"] == []


def test_inventory_escapes_wildcards_and_stably_orders_duplicate_usernames(
    client: TestClient, session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as session:
        session.add_all([
            Identity(source=source, external_id="same", username="same",
                     display_name=name, identity_type=IdentityType.HUMAN)
            for source, name in [("github", "100%_literal"), ("azure", "100xxliteral")]
        ])
    first = client.get("/v1/identities/inventory?limit=1").json()["items"][0]
    second = client.get("/v1/identities/inventory?limit=1&offset=1").json()["items"][0]
    assert first["id"] < second["id"]
    assert client.get("/v1/identities/inventory", params={"q": "%_"}).json()["total"] == 1


@pytest.mark.parametrize("params", [{"limit": 201}, {"offset": -1}, {"q": "x" * 256}])
def test_inventory_validates_bounds(client: TestClient, params: dict) -> None:
    assert client.get("/v1/identities/inventory", params=params).status_code == 422


def test_identity_detail_returns_not_found_for_another_tenant_object_id() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
        info={"tenant_id": "tenant-a"},
    )
    with factory.begin() as session:
        other_tenant_identity = Identity(
            tenant_id="tenant-b",
            source="keycloak",
            external_id="tenant-b-user",
            username="tenant-b-user",
            identity_type=IdentityType.HUMAN,
            display_name="Tenant B User",
            active=True,
        )
        session.add(other_tenant_identity)
        visible_identity = Identity(
            tenant_id="tenant-a", source="keycloak", external_id="tenant-a-user",
            username="tenant-b-search-match", display_name="Visible search match",
            identity_type=IdentityType.HUMAN,
        )
        session.add(visible_identity)

    def override_session() -> Generator[Session]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = override_session
    try:
        response = TestClient(app).get(f"/v1/identities/{other_tenant_identity.id}")
        inventory = TestClient(app).get("/v1/identities/inventory?q=tenant-b")
    finally:
        app.dependency_overrides.clear()
        engine.dispose()

    assert response.status_code == 404
    assert response.json() == {"detail": "Identity not found"}
    assert inventory.status_code == 200
    assert [item["id"] for item in inventory.json()["items"]] == [str(visible_identity.id)]
    assert inventory.json()["total"] == 1
