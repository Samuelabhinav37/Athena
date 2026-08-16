from collections.abc import Generator

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import (
    AccessGrant,
    AuditEvent,
    Base,
    EffectiveEntitlement,
    Identity,
    IdentityType,
    Permission,
    ProvenanceEdge,
    Resource,
    Role,
)
from athena.services.demo_scenario import DemoScenarioService
from athena.services.provenance import governance_gaps
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def provenance_session() -> Generator[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        developer = Role(
            source="keycloak",
            external_id="role-developer",
            name="developer",
        )
        alice = Identity(
            source="keycloak",
            external_id="user-alice",
            username="alice",
            identity_type=IdentityType.HUMAN,
            display_name="Alice Johnson",
            department="engineering",
            roles=[developer],
        )
        bob = Identity(
            source="keycloak",
            external_id="user-bob",
            username="bob",
            identity_type=IdentityType.HUMAN,
            display_name="Bob Martinez",
            department="devops",
        )
        session.add_all([alice, bob])
        session.commit()
        yield session
    engine.dispose()


def test_demo_scenario_is_idempotent_and_flags_ungoverned_access(
    provenance_session: Session,
) -> None:
    first = DemoScenarioService(provenance_session).seed()
    second = DemoScenarioService(provenance_session).seed()

    assert first == {"grants_created": 3, "entitlements_materialized": 3}
    assert second == {"grants_created": 0, "entitlements_materialized": 3}
    assert provenance_session.scalar(select(func.count()).select_from(Resource)) == 3
    assert provenance_session.scalar(select(func.count()).select_from(Permission)) == 3
    assert provenance_session.scalar(select(func.count()).select_from(AccessGrant)) == 3
    assert provenance_session.scalar(select(func.count()).select_from(EffectiveEntitlement)) == 3
    assert provenance_session.scalar(select(func.count()).select_from(AuditEvent)) == 1

    production = provenance_session.scalar(
        select(EffectiveEntitlement)
        .join(EffectiveEntitlement.permission)
        .where(Permission.name == "Production Database Read")
    )
    assert production is not None
    assert governance_gaps(production.grant) == [
        "missing_business_reason",
        "missing_expiration",
    ]
    assert [edge.relationship_type for edge in production.provenance_edges] == [
        "direct_grant",
        "applies_to",
    ]


def test_entitlement_api_returns_ordered_provenance_and_governance(
    provenance_session: Session,
) -> None:
    DemoScenarioService(provenance_session).seed()
    alice = provenance_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None

    def override_session() -> Generator[Session]:
        yield provenance_session

    app.dependency_overrides[get_db_session] = override_session
    try:
        response = TestClient(app).get(f"/v1/identities/{alice.id}/entitlements")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 3
    production = next(
        item for item in payload if item["permission"]["resource"]["name"] == "Production Database"
    )
    assert production["governance"]["status"] == "ungoverned"
    assert production["governance"]["gaps"] == [
        "missing_business_reason",
        "missing_expiration",
    ]
    assert [edge["relationship"] for edge in production["provenance"]] == [
        "direct_grant",
        "applies_to",
    ]

    github = next(
        item for item in payload if item["permission"]["resource"]["name"] == "GitHub"
    )
    assert github["governance"]["status"] == "governed"
    assert [edge["relationship"] for edge in github["provenance"]] == [
        "assigned_role",
        "grants",
        "applies_to",
    ]


def test_audit_events_cannot_be_updated(provenance_session: Session) -> None:
    DemoScenarioService(provenance_session).seed()
    audit_event = provenance_session.scalar(select(AuditEvent))
    assert audit_event is not None
    audit_event.reason = "attempted rewrite"

    with pytest.raises(ValueError, match="append-only"):
        provenance_session.commit()
    provenance_session.rollback()


def test_provenance_edges_have_unique_order(provenance_session: Session) -> None:
    DemoScenarioService(provenance_session).seed()
    edges = list(
        provenance_session.scalars(
            select(ProvenanceEdge).order_by(
                ProvenanceEdge.entitlement_id, ProvenanceEdge.sequence
            )
        )
    )

    sequences: dict[object, list[int]] = {}
    for edge in edges:
        sequences.setdefault(edge.entitlement_id, []).append(edge.sequence)
    assert all(values == list(range(len(values))) for values in sequences.values())
