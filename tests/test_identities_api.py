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
