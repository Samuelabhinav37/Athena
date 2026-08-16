from collections.abc import Generator

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import AnomalyModelRun, AnomalyResult, Identity
from athena.services.drift_scenario import DriftScenarioService
from athena.services.peer_anomaly import FEATURES, PeerAnomalyService
from athena.services.risk_analytics import RiskAnalyticsService
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from test_risk_analytics import risk_session  # noqa: F401


def _run(session: Session):
    DriftScenarioService(session).apply()
    alice = session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(session).assess(alice)
    return alice, PeerAnomalyService(session).run(alice)


def test_peer_anomaly_is_reproducible_and_advisory(  # noqa: F811
    risk_session: Session,  # noqa: F811
) -> None:
    alice, first = _run(risk_session)
    second = PeerAnomalyService(risk_session).run(alice)
    assert first.training_fingerprint == second.training_fingerprint
    assert first.is_anomaly is True
    assert second.is_anomaly is True
    assert first.decision_score == pytest.approx(second.decision_score)
    assert first.peer_anomaly_count <= 5
    assert not ({"age", "gender", "race", "ethnicity", "disability"} & set(FEATURES))
    run = risk_session.get(AnomalyModelRun, first.run_id)
    assert run is not None
    assert run.sample_size == 100
    assert run.summary["advisory_only"] is True
    assert len(run.results) == 101


def test_peer_anomaly_api_exposes_model_evidence(  # noqa: F811
    risk_session: Session,  # noqa: F811
) -> None:
    alice, result = _run(risk_session)

    def override_session() -> Generator[Session]:
        yield risk_session

    app.dependency_overrides[get_db_session] = override_session
    try:
        response = TestClient(app).get(f"/v1/identities/{alice.id}/anomaly-assessments")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()[0]
    assert payload["id"] == str(result.result_id)
    assert payload["is_anomaly"] is True
    assert payload["run"]["algorithm"] == "IsolationForest"
    assert payload["run"]["summary"]["advisory_only"] is True


def test_anomaly_evidence_is_immutable(risk_session: Session) -> None:  # noqa: F811
    _, result = _run(risk_session)
    evidence = risk_session.get(AnomalyResult, result.result_id)
    assert evidence is not None
    evidence.is_anomaly = False
    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()
