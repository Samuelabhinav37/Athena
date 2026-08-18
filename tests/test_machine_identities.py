from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, Identity, IdentityType
from athena.services.machine_identities import load_machine_identity_posture
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def machine_session() -> Generator[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        session.add_all(
            [
                Identity(
                    source="aws_iam",
                    external_id="role-1",
                    username="deploy-role",
                    identity_type=IdentityType.SERVICE_ACCOUNT,
                    display_name="Deploy Role",
                    active=True,
                    source_metadata={"account_id": "123456789012", "trust_policy": {}},
                ),
                Identity(
                    source="internal",
                    external_id="client-1",
                    username="billing-client",
                    identity_type=IdentityType.API_CLIENT,
                    display_name="Billing Client",
                    active=True,
                    source_metadata={
                        "owner": "platform-team",
                        "access_keys": [{"status": "Active", "age_days": 120}],
                    },
                ),
                Identity(
                    source="keycloak",
                    external_id="human-1",
                    username="alice",
                    identity_type=IdentityType.HUMAN,
                    display_name="Alice",
                    active=True,
                ),
            ]
        )
        session.commit()
        yield session
    engine.dispose()


def test_machine_posture_is_deterministic_and_excludes_humans(
    machine_session: Session,
) -> None:
    posture = load_machine_identity_posture(machine_session)

    assert [item.username for item in posture] == ["deploy-role", "billing-client"]
    assert [finding.code for finding in posture[0].findings] == [
        "missing_owner",
        "usage_unknown",
    ]
    assert [finding.code for finding in posture[1].findings] == [
        "usage_unknown",
        "stale_credential",
    ]
    assert posture[1].owner == "platform-team"


def test_machine_identity_api_is_bounded(machine_session: Session) -> None:
    app.dependency_overrides[get_db_session] = lambda: machine_session
    try:
        with TestClient(app) as client:
            response = client.get("/v1/machine-identities?limit=1&offset=1")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert [item["username"] for item in response.json()] == ["billing-client"]
    assert "source_metadata" not in response.json()[0]


def test_machine_identity_api_rejects_unbounded_limit(machine_session: Session) -> None:
    app.dependency_overrides[get_db_session] = lambda: machine_session
    try:
        with TestClient(app) as client:
            response = client.get("/v1/machine-identities?limit=201")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422


def test_machine_identity_uses_connector_role_last_used_evidence(
    machine_session: Session,
) -> None:
    identity = Identity(
        source="aws_iam",
        external_id="role-with-usage",
        username="deployer",
        display_name="deployer",
        identity_type=IdentityType.SERVICE_ACCOUNT,
        active=True,
        source_metadata={
            "owner": "platform-team",
            "role_last_used_at": "2026-08-01T00:00:00+00:00",
        },
    )
    machine_session.add(identity)
    machine_session.commit()

    posture = next(
        item
        for item in load_machine_identity_posture(machine_session)
        if item.identity_id == identity.id
    )

    assert posture.owner == "platform-team"
    assert posture.last_used_at == datetime(2026, 8, 1, tzinfo=UTC)
    assert all(finding.code != "usage_unknown" for finding in posture.findings)
