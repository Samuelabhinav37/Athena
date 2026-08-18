from collections.abc import Generator
from pathlib import Path

import pytest
from athena.auth import Principal, get_current_principal
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, Identity, IdentityType
from athena.services.evidence_report import EvidenceReportService
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


def test_evidence_report_is_deterministic_and_excludes_llm_output(
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory.begin() as session:
        session.add(
            Identity(
                source="keycloak",
                external_id="alice",
                username="alice",
                identity_type=IdentityType.HUMAN,
                display_name="Alice",
                active=True,
            )
        )
    with session_factory() as session:
        service = EvidenceReportService(session, Path("controls"))
        first = service.build()
        second = service.build()
        markdown = service.markdown(first)

    assert first.inventory["identities"] == 1
    assert first.inventory["active_identities"] == 1
    assert first.evidence_digest == second.evidence_digest
    assert len(first.controls) == 3
    assert any(
        limitation.startswith("Generated LLM explanations are excluded")
        for limitation in first.limitations
    )
    assert first.evidence_digest in markdown
    assert "not authoritative report evidence" in markdown


def test_administrator_can_download_json_and_markdown_reports(client: TestClient) -> None:
    json_response = client.get("/v1/reports/evidence")
    markdown_response = client.get("/v1/reports/evidence.md")

    assert json_response.status_code == 200
    assert len(json_response.json()["evidence_digest"]) == 64
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/plain")
    assert "# Athena Authorization Evidence Report" in markdown_response.text


def test_viewer_cannot_download_full_evidence_report(
    client: TestClient,
) -> None:
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "viewer-subject", "alice", frozenset({"athena-viewer"}), {}
    )
    try:
        response = client.get("/v1/reports/evidence")
    finally:
        app.dependency_overrides.pop(get_current_principal, None)

    assert response.status_code == 403
    assert response.json() == {"detail": "Role athena-administrator or higher is required"}
