from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from athena.auth import Principal, get_current_principal
from athena.database import get_db_session
from athena.main import app
from athena.models import (
    AccessObservation,
    Base,
    EffectiveEntitlement,
    Identity,
    IdentityType,
    PolicyDecision,
    PolicyEvaluation,
    ReviewCase,
    ReviewDecision,
    ReviewEvent,
    ReviewStatus,
    RiskAssessment,
    RiskFindingType,
    RiskLevel,
    Role,
    RoleTransition,
)
from athena.services.demo_scenario import DemoScenarioService
from athena.services.drift_scenario import DriftScenarioService
from athena.services.remediation import RemediationService, load_case
from athena.services.risk_analytics import MODEL_VERSION, RiskAnalyticsService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.mark.parametrize(
    ("used_days", "observed_days", "expected"),
    [(None, 0, "unknown"), (10, 0, "recent"), (90, 0, "stale"),
     (-1, 0, "invalid"), (10, -1, "invalid"), (1, 2, "invalid"),
     (120, 2, "unknown")],
)
def test_activity_evidence_does_not_invent_inactivity(
    risk_session: Session, used_days: int | None, observed_days: int, expected: str,
) -> None:
    now = datetime.now(UTC)
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    entitlement = risk_session.scalar(select(EffectiveEntitlement).where(
        EffectiveEntitlement.identity_id == alice.id,
    ))
    risk_session.add(AccessObservation(
        entitlement=entitlement, source="test", external_id="activity-contract",
        last_used_at=None if used_days is None else now - timedelta(days=used_days),
        observed_at=now - timedelta(days=observed_days),
    ))
    risk_session.commit()
    result = RiskAnalyticsService(risk_session).assess(alice)
    assessment = risk_session.get(RiskAssessment, result.assessment_id)
    finding = next(f for f in assessment.findings if f.entitlement_id == entitlement.id)
    activity = finding.factors["time_since_use"]
    assert activity["status"] == expected
    if expected in {"unknown", "invalid"}:
        assert activity["value"] == 1.0
        assert activity["treatment"] == "uncertainty_reserve"
        assert finding.finding_type != RiskFindingType.STALE_ACCESS
        assert "not evidence of inactivity" in finding.explanation
    else:
        assert activity["treatment"] == "observed_age"


def test_missing_activity_and_previous_assessment_are_preserved(risk_session: Session) -> None:
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    legacy = RiskAssessment(
        identity=alice, model_version="access-decay-v1", score=42,
        level=RiskLevel.MEDIUM, peer_definition={}, summary={"historical": True},
    )
    risk_session.add(legacy)
    risk_session.commit()
    result = RiskAnalyticsService(risk_session).assess(alice)
    current = risk_session.get(RiskAssessment, result.assessment_id)
    assert result.model_version == "access-decay-v2"
    assert all(f.factors["time_since_use"]["status"] == "unknown" for f in current.findings)
    assert all(f.finding_type != RiskFindingType.STALE_ACCESS for f in current.findings)
    app.dependency_overrides[get_db_session] = lambda: risk_session
    try:
        response = TestClient(app).get(f"/v1/identities/{alice.id}/risk-assessments")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = next(item for item in response.json() if item["id"] == str(current.id))
    assert payload["model_version"] == "access-decay-v2"
    assert all(
        finding["factors"]["time_since_use"]["treatment"] == "uncertainty_reserve"
        and "not evidence of inactivity" in finding["explanation"]
        for finding in payload["findings"]
    )
    risk_session.refresh(legacy)
    assert (legacy.model_version, legacy.score, legacy.summary) == (
        "access-decay-v1", 42, {"historical": True},
    )


@pytest.fixture
def risk_session() -> Generator[Session]:
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
        security = Role(
            source="keycloak",
            external_id="role-security",
            name="security-analyst",
        )
        alice = Identity(
            source="keycloak",
            external_id="user-alice",
            username="alice",
            identity_type=IdentityType.HUMAN,
            display_name="Alice Johnson",
            department="engineering",
            job_title="Developer",
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
        charlie = Identity(
            source="keycloak",
            external_id="user-charlie",
            username="charlie",
            identity_type=IdentityType.HUMAN,
            display_name="Charlie Kim",
            department="security",
            job_title="Security Analyst",
            roles=[security],
        )
        session.add_all([alice, bob, charlie])
        session.commit()
        DemoScenarioService(session).seed()
        for entitlement in session.scalars(select(EffectiveEntitlement)):
            failed = entitlement.permission.resource.external_id == "production-database"
            session.add(
                PolicyEvaluation(
                    entitlement=entitlement,
                    engine="opa",
                    policy_path="athena/authorization/evaluate",
                    policy_version="test-policy-version",
                    decision=PolicyDecision.FAIL if failed else PolicyDecision.PASS,
                    input_snapshot={},
                    violations=[{"code": "TEST_FAILURE"}] if failed else [],
                )
            )
        session.commit()
        yield session
    engine.dispose()


def test_drift_scenario_is_idempotent_and_preserves_retained_access(
    risk_session: Session,
) -> None:
    first = DriftScenarioService(risk_session).apply()
    second = DriftScenarioService(risk_session).apply()

    assert first == {
        "transitions_created": 1,
        "observations_created": 3,
        "retained_entitlements": 3,
    }
    assert second == {
        "transitions_created": 0,
        "observations_created": 0,
        "retained_entitlements": 3,
    }
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    assert alice.department == "security"
    assert [role.name for role in alice.roles] == ["security-analyst"]
    assert risk_session.scalar(select(func.count()).select_from(RoleTransition)) == 1
    assert risk_session.scalar(select(func.count()).select_from(AccessObservation)) == 3
    assert risk_session.scalar(
        select(func.count()).select_from(EffectiveEntitlement).where(
            EffectiveEntitlement.active.is_(True)
        )
    ) == 3


def test_risk_assessment_is_explainable_and_critical(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None

    result = RiskAnalyticsService(risk_session).assess(alice)

    assert result.model_version == MODEL_VERSION
    assert result.score == 100.0
    assert result.level == RiskLevel.CRITICAL
    assert result.findings == 3
    assessment = risk_session.get(RiskAssessment, result.assessment_id)
    assert assessment is not None
    assert assessment.peer_definition == {
        "department": "security",
        "roles": ["security-analyst"],
        "peer_count": 1,
        "peers": ["charlie"],
    }
    assert assessment.summary == {
        "active_entitlements": 3,
        "retained_entitlements": 3,
        "peer_deviations": 3,
        "high_risk_entitlements": 1,
    }
    production = next(
        finding
        for finding in assessment.findings
        if finding.entitlement.permission.resource.external_id == "production-database"
    )
    assert production.score == 100.0
    assert all(
        production.factors[name]["value"] == 1.0
        for name in (
            "retained_access",
            "privilege",
            "sensitivity",
            "time_since_use",
            "peer_deviation",
            "policy_risk",
            "authentication_risk",
        )
    )


def test_risk_assessment_api_exposes_factors(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)

    def override_session() -> Generator[Session]:
        yield risk_session

    app.dependency_overrides[get_db_session] = override_session
    try:
        response = TestClient(app).get(f"/v1/identities/{alice.id}/risk-assessments")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["score"] == 100.0
    assert payload[0]["level"] == "critical"
    assert len(payload[0]["findings"]) == 3
    production = next(
        finding
        for finding in payload[0]["findings"]
        if finding["resource"] == "Production Database"
    )
    assert production["factors"]["policy_risk"] == {"value": 1.0, "weight": 15.0}


def test_risk_assessments_are_immutable(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    result = RiskAnalyticsService(risk_session).assess(alice)
    assessment = risk_session.get(RiskAssessment, result.assessment_id)
    assert assessment is not None
    assessment.score = 0

    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()


def test_human_review_records_append_only_decision_without_executing_access(
    risk_session: Session,
) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)
    service = RemediationService(risk_session)

    opened = service.open_for_latest_evidence(alice, actor="athena-risk-engine")
    case = load_case(risk_session, opened.case_id)
    assert case is not None
    assert case.status == ReviewStatus.OPEN
    assert case.events[0].execution_status == "not_applicable"

    service.assign(case, owner="charlie", actor="security-queue", reason="Queue assignment")
    decided = service.decide(
        case, ReviewDecision.REVOKE, actor="charlie",
        reason="Access is unrelated to Alice's current Security role",
    )
    assert decided.status == ReviewStatus.RESOLVED
    assert decided.resolution == ReviewDecision.REVOKE
    assert len(case.events) == 3
    assert case.events[-1].execution_status == "pending"
    assert all(entitlement.active for entitlement in risk_session.scalars(
        select(EffectiveEntitlement).where(EffectiveEntitlement.identity_id == alice.id)
    ))


def test_only_assigned_owner_can_decide_review(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)
    service = RemediationService(risk_session)
    opened = service.open_for_latest_evidence(alice, actor="risk-engine")
    case = load_case(risk_session, opened.case_id)
    assert case is not None
    service.assign(case, owner="charlie", actor="queue", reason="Assign analyst")
    with pytest.raises(ValueError, match="assigned owner"):
        service.decide(case, ReviewDecision.RETAIN, actor="frank",
                       reason="Unauthorized reviewer tried to retain access")


def test_review_api_rejects_implicit_targets_and_username_only_assignment(
    risk_session: Session,
) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    RiskAnalyticsService(risk_session).assess(alice)
    legacy = RemediationService(risk_session).open_for_latest_evidence(alice, actor="fixture")
    app.dependency_overrides[get_db_session] = lambda: risk_session
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "user-charlie", "charlie", frozenset({"athena-reviewer"}), {}
    )
    try:
        client = TestClient(app)
        opened = client.post("/v1/reviews", json={"identity_id": str(alice.id)})
        assigned = client.post(f"/v1/reviews/{legacy.case_id}/assign", json={
            "owner": "charlie", "reason": "Assign analyst",
        })
        decided = client.post(f"/v1/reviews/{legacy.case_id}/decide", json={
            "decision": "exception", "reason": "Attempt username-only approval",
        })
    finally:
        app.dependency_overrides.clear()
    assert opened.status_code == assigned.status_code == decided.status_code == 409
    assert "exactly one" in opened.json()["detail"]
    assert "owner_id" in assigned.json()["detail"]
    assert risk_session.get(ReviewCase, legacy.case_id).status == ReviewStatus.OPEN


def test_review_detail_returns_not_found_for_another_tenant_case_id(
    risk_session: Session,
) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)
    opened = RemediationService(risk_session).open_for_latest_evidence(
        alice, actor="risk-engine"
    )
    risk_session.info["tenant_id"] = "tenant-with-no-review-evidence"
    app.dependency_overrides[get_db_session] = lambda: risk_session
    try:
        response = TestClient(app).get(f"/v1/reviews/{opened.case_id}")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json() == {"detail": "Review not found"}


def test_review_events_are_immutable(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)
    opened = RemediationService(risk_session).open_for_latest_evidence(alice, actor="risk-engine")
    event = risk_session.scalar(select(ReviewEvent).where(ReviewEvent.case_id == opened.case_id))
    assert event is not None
    event.reason = "tampered"
    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()
