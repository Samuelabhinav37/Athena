from collections.abc import Generator

import athena.services.peer_anomaly as peer_anomaly
import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import AnomalyModelRun, AnomalyResult, Identity, ReviewDecision
from athena.services.drift_scenario import DriftScenarioService
from athena.services.peer_anomaly import (
    COHORT_POLICY_VERSION,
    FEATURES,
    GovernedCohortSelector,
    PeerAnomalyService,
)
from athena.services.remediation import RemediationService, load_case
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
    assert run.peer_definition["policy_version"] == COHORT_POLICY_VERSION
    assert run.peer_definition["selected"] == "synthetic_security"
    assert run.peer_definition["synthetic_fallback"] is True
    assert run.summary["peer_alert_rate"] == 0.05
    assert run.summary["peer_alert_rate_is_false_positive_rate"] is False
    assert run.summary["reviewed_label_metrics"]["false_positive_rate"] is None
    assert run.summary["drift"]["status"] == "baseline_established"
    assert len(run.results) == 101

    second_run = risk_session.get(AnomalyModelRun, second.run_id)
    assert second_run is not None
    assert second_run.summary["drift"]["status"] == "stable"
    assert second_run.summary["drift"]["max_feature_shift"] == 0.0


def test_governed_selector_uses_real_peers_when_minimum_is_met(risk_session: Session) -> None:  # noqa: F811
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    charlie = risk_session.scalar(select(Identity).where(Identity.username == "charlie"))
    assert alice is not None and charlie is not None
    RiskAnalyticsService(risk_session).assess(charlie)

    selection = GovernedCohortSelector(risk_session, minimum_size=1).select(alice)

    assert selection.definition["selected"] == "department_and_role"
    assert selection.definition["synthetic_fallback"] is False
    assert selection.definition["candidate_counts"]["department_and_role"] == 1
    assert selection.entries[0].subject_key == "charlie"
    assert selection.entries[0].synthetic is False


def test_reviewed_false_positive_rate_uses_human_labels(risk_session: Session) -> None:  # noqa: F811
    alice, _ = _run(risk_session)
    remediation = RemediationService(risk_session)
    opened = remediation.open_for_latest_evidence(alice, actor="risk-engine")
    case = load_case(risk_session, opened.case_id)
    assert case is not None
    remediation.assign(case, owner="charlie", actor="queue", reason="Assign analyst")
    remediation.decide(
        case, ReviewDecision.EXCEPTION, actor="charlie",
        reason="Expected access is covered by an approved temporary exception",
    )

    calibrated = PeerAnomalyService(risk_session).run(alice)
    run = risk_session.get(AnomalyModelRun, calibrated.run_id)
    assert run is not None
    assert run.summary["reviewed_label_metrics"] == {
        "reviewed_anomalies": 1,
        "false_positive_labels": 1,
        "false_positive_rate": 1.0,
        "label_definition": "retain_or_exception",
    }


def test_feature_drift_is_detected_against_previous_baseline(
    risk_session: Session, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    alice, _ = _run(risk_session)
    shifted = peer_anomaly.synthetic_security_cohort()
    for row in shifted:
        row["entitlement_count"] += 10.0
    monkeypatch.setattr(peer_anomaly, "synthetic_security_cohort", lambda: shifted)

    outcome = PeerAnomalyService(risk_session).run(alice)
    run = risk_session.get(AnomalyModelRun, outcome.run_id)
    assert run is not None
    assert outcome.drift_detected is True
    assert run.summary["drift"]["status"] == "drift_detected"
    assert run.summary["drift"]["max_feature_shift"] >= 0.25


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
