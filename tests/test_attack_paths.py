import uuid
from collections.abc import Generator

import pytest
from athena.config import Settings
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, Identity, IdentityType, Role
from athena.services.attack_paths import (
    AttackPath,
    AttackPathError,
    GraphNode,
    Neo4jAttackPathAdapter,
    build_projection,
)
from athena.services.demo_scenario import DemoScenarioService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def graph_session() -> Generator[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        developer = Role(source="keycloak", external_id="developer", name="developer")
        session.add_all(
            [
                Identity(
                    source="keycloak",
                    external_id="alice",
                    username="alice",
                    identity_type=IdentityType.HUMAN,
                    display_name="Alice Johnson",
                    department="engineering",
                    roles=[developer],
                ),
                Identity(
                    source="keycloak",
                    external_id="bob",
                    username="bob",
                    identity_type=IdentityType.HUMAN,
                    display_name="Bob Martinez",
                    department="devops",
                ),
            ]
        )
        session.commit()
        DemoScenarioService(session).seed()
        yield session
    engine.dispose()


def test_projection_reuses_nodes_and_preserves_privileged_lineage(
    graph_session: Session,
) -> None:
    projection = build_projection(graph_session)

    assert len(projection.nodes) == len({node.id for node in projection.nodes})
    assert len(projection.edges) == 8
    assert any(edge.privileged for edge in projection.edges)
    assert {node.kind for node in projection.nodes} >= {"identity", "permission", "resource"}


def test_adapter_requires_explicit_graph_configuration() -> None:
    with pytest.raises(AttackPathError, match="not configured"):
        Neo4jAttackPathAdapter(Settings(database_url="sqlite://"))


def test_attack_path_api_returns_bounded_advisory_paths(
    monkeypatch: pytest.MonkeyPatch, graph_session: Session
) -> None:
    identity_id = graph_session.query(Identity.id).filter_by(username="alice").scalar()
    assert identity_id is not None
    resource_id = uuid.uuid4()

    class FakeAdapter:
        def __init__(self, _: Settings) -> None:
            pass

        def __enter__(self) -> "FakeAdapter":
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def find_privileged_paths(
            self, requested_identity: uuid.UUID, *, max_depth: int, limit: int
        ) -> list[AttackPath]:
            assert requested_identity == identity_id
            assert (max_depth, limit) == (4, 10)
            return [
                AttackPath(
                    nodes=(
                        GraphNode(str(identity_id), "identity", "Alice Johnson"),
                        GraphNode(str(resource_id), "resource", "Production Database"),
                    ),
                    relationships=("direct_grant", "applies_to"),
                )
            ]

    monkeypatch.setattr("athena.routes.attack_paths.Neo4jAttackPathAdapter", FakeAdapter)
    app.dependency_overrides[get_db_session] = lambda: graph_session
    try:
        with TestClient(app) as client:
            response = client.get(
                f"/v1/attack-paths/identities/{identity_id}?max_depth=4&limit=10"
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()[0]["nodes"][1]["kind"] == "resource"
    assert response.json()[0]["relationships"] == ["direct_grant", "applies_to"]


def test_attack_path_api_rejects_unbounded_depth(graph_session: Session) -> None:
    app.dependency_overrides[get_db_session] = lambda: graph_session
    with TestClient(app) as client:
        response = client.get(f"/v1/attack-paths/identities/{uuid.uuid4()}?max_depth=9")
    app.dependency_overrides.clear()

    assert response.status_code == 422
