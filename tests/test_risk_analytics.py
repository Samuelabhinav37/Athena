from collections.abc import Generator

import pytest
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
    RiskAssessment,
    RiskLevel,
    Role,
    RoleTransition,
)
from athena.services.demo_scenario import DemoScenarioService
from athena.services.drift_scenario import DriftScenarioService
from athena.services.risk_analytics import MODEL_VERSION, RiskAnalyticsService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


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
