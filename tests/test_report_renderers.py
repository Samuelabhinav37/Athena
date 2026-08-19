from collections.abc import Generator
from pathlib import Path

import pytest
from athena.models import Base, Identity, IdentityType
from athena.services.evidence_report import EvidenceReportService
from athena.services.report_renderers import (
    RENDERERS,
    EvidenceRenderError,
    JSONEvidenceRenderer,
    MarkdownEvidenceRenderer,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def evidence_report() -> Generator:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
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
    with factory() as session:
        yield EvidenceReportService(session, Path("controls")).build()
    engine.dispose()


def test_json_and_markdown_renderers_are_deterministic(evidence_report) -> None:
    for renderer in (JSONEvidenceRenderer(), MarkdownEvidenceRenderer()):
        first = renderer.render(evidence_report)
        second = renderer.render(evidence_report)

        assert first == second
        assert first.source_evidence_digest == evidence_report.evidence_digest
        assert len(first.content_sha256) == 64
        assert b"Generated LLM explanations" in first.content


def test_renderers_reject_tampered_authoritative_facts(evidence_report) -> None:
    evidence_report.inventory["identities"] = 999

    with pytest.raises(EvidenceRenderError, match="digest does not match"):
        JSONEvidenceRenderer().render(evidence_report)


def test_registry_declares_only_implemented_formats() -> None:
    assert set(RENDERERS) == {"json", "markdown"}
    assert all(renderer.manifest.deterministic for renderer in RENDERERS.values())
    assert all(renderer.manifest.authoritative_facts_only for renderer in RENDERERS.values())
