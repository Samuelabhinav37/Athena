from collections.abc import Generator
from dataclasses import dataclass, field

import pytest
from athena.auth import Principal, get_current_principal
from athena.database import get_db_session
from athena.main import app
from athena.models import (
    Base,
    EffectiveEntitlement,
    ExecutionStatus,
    Identity,
    IdentityType,
    PolicyDecision,
    PolicyEvaluation,
    RemediationExecutionEvent,
    ReviewDecision,
    Role,
)
from athena.services.demo_scenario import DemoScenarioService
from athena.services.drift_scenario import DriftScenarioService
from athena.services.execution import (
    ExecutionError,
    ExecutionService,
    ExecutionTarget,
    VerificationResult,
)
from athena.services.remediation import RemediationService, load_case
from athena.services.risk_analytics import RiskAnalyticsService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
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
        developer = Role(source="keycloak", external_id="role-developer", name="developer")
        security = Role(
            source="keycloak", external_id="role-security", name="security-analyst"
        )
        session.add_all(
            [
                Identity(
                    source="keycloak",
                    external_id="user-bob",
                    username="bob",
                    identity_type=IdentityType.HUMAN,
                    display_name="Bob Martinez",
                    department="devops",
                ),
                Identity(
                    source="keycloak",
                    external_id="user-alice",
                    username="alice",
                    identity_type=IdentityType.HUMAN,
                    display_name="Alice Johnson",
                    department="engineering",
                    job_title="Developer",
                    roles=[developer],
                ),
                Identity(
                    source="keycloak",
                    external_id="user-charlie",
                    username="charlie",
                    identity_type=IdentityType.HUMAN,
                    display_name="Charlie Kim",
                    department="security",
                    roles=[security],
                ),
            ]
        )
        session.commit()
        DemoScenarioService(session).seed()
        for entitlement in session.scalars(select(EffectiveEntitlement)):
            failed = entitlement.permission.resource.external_id == "production-database"
            session.add(
                PolicyEvaluation(
                    entitlement=entitlement,
                    engine="opa",
                    policy_path="athena/authorization/evaluate",
                    policy_version="execution-test-policy",
                    decision=PolicyDecision.FAIL if failed else PolicyDecision.PASS,
                    input_snapshot={},
                    violations=[{"code": "TEST_FAILURE"}] if failed else [],
                )
            )
        session.commit()
        yield session
    engine.dispose()


@dataclass
class FakeAdapter:
    source: str
    verified: bool = True
    fail: bool = False
    calls: list[tuple[ExecutionTarget, str]] = field(default_factory=list)

    def revoke(self, target: ExecutionTarget, idempotency_key: str) -> dict:
        self.calls.append((target, idempotency_key))
        if self.fail:
            raise RuntimeError("sanitized upstream failure")
        return {"request_id": "adapter-request-1", "duplicate": len(self.calls) > 1}

    def verify_revoked(self, target: ExecutionTarget) -> VerificationResult:
        return VerificationResult(
            self.verified,
            {"grant_external_id": target.grant_external_id, "present": not self.verified},
        )


def approved_case(session: Session):
    DriftScenarioService(session).apply()
    alice = session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(session).assess(alice)
    remediation = RemediationService(session)
    opened = remediation.open_for_latest_evidence(alice, actor="athena-risk-engine")
    case = load_case(session, opened.case_id)
    assert case is not None and case.entitlement_id is not None
    remediation.assign(case, owner="charlie", actor="charlie", reason="Assigned for review")
    remediation.decide(
        case,
        ReviewDecision.REVOKE,
        actor="charlie",
        reason="Confirmed stale production access must be removed",
    )
    return case


def test_execution_requires_approved_revoke_and_is_idempotent(risk_session: Session) -> None:
    DriftScenarioService(risk_session).apply()
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    assert alice is not None
    RiskAnalyticsService(risk_session).assess(alice)
    opened = RemediationService(risk_session).open_for_latest_evidence(alice, actor="engine")
    pending_case = load_case(risk_session, opened.case_id)
    assert pending_case is not None
    service = ExecutionService(risk_session)

    with pytest.raises(ExecutionError, match="resolved revoke"):
        service.request(pending_case, "frank", "review-not-approved")

    remediation = RemediationService(risk_session)
    remediation.assign(pending_case, "charlie", "charlie", "Assign reviewer")
    remediation.decide(
        pending_case,
        ReviewDecision.REVOKE,
        "charlie",
        "Confirmed stale access should be revoked",
    )
    first = service.request(pending_case, "frank", "revoke-alice-production-db")
    second = service.request(pending_case, "frank", "revoke-alice-production-db")

    assert first.id == second.id
    assert first.status == ExecutionStatus.PENDING
    assert first.requested_by == "frank"
    assert first.before_evidence["review_decision"] == "revoke"
    assert [event.action for event in first.events] == ["requested"]


def test_verified_execution_revokes_local_evidence_and_replay_is_noop(
    risk_session: Session,
) -> None:
    case = approved_case(risk_session)
    service = ExecutionService(risk_session)
    execution = service.request(case, "frank", "verified-revocation")
    adapter = FakeAdapter(source=execution.source)

    completed = service.run(execution, "athena-executor", adapter)
    replayed = service.run(execution, "athena-executor", adapter)
    entitlement = risk_session.get(EffectiveEntitlement, execution.entitlement_id)

    assert completed.id == replayed.id
    assert completed.status == ExecutionStatus.SUCCEEDED
    assert completed.attempt_count == 1
    assert len(adapter.calls) == 1
    assert entitlement is not None and entitlement.active is False
    assert entitlement.grant.revoked_at is not None
    assert [event.action for event in completed.events] == ["requested", "started", "verified"]


def test_failure_and_verification_failure_preserve_active_access(risk_session: Session) -> None:
    case = approved_case(risk_session)
    service = ExecutionService(risk_session)
    execution = service.request(case, "frank", "failed-revocation")
    failed = service.run(execution, "athena-executor", FakeAdapter(execution.source, fail=True))
    entitlement = risk_session.get(EffectiveEntitlement, execution.entitlement_id)

    assert failed.status == ExecutionStatus.FAILED
    assert failed.error == "RuntimeError: remediation adapter failed"
    assert entitlement is not None and entitlement.active is True

    retried = service.run(
        execution,
        "athena-executor",
        FakeAdapter(execution.source, verified=False),
    )
    assert retried.status == ExecutionStatus.VERIFICATION_FAILED
    assert retried.attempt_count == 2
    assert entitlement.active is True


def test_execution_events_are_immutable(risk_session: Session) -> None:
    case = approved_case(risk_session)
    execution = ExecutionService(risk_session).request(case, "frank", "immutable-events")
    event = execution.events[0]

    event.action = "tampered"
    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()

    stored = risk_session.scalar(
        select(RemediationExecutionEvent).where(RemediationExecutionEvent.id == event.id)
    )
    assert stored is not None and stored.action == "requested"


def test_execution_api_requires_administrator_and_uses_authenticated_actor(
    risk_session: Session,
) -> None:
    case = approved_case(risk_session)

    def override_session() -> Generator[Session]:
        yield risk_session

    app.dependency_overrides[get_db_session] = override_session
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "user-alice", "alice", frozenset({"athena-viewer"}), {}
    )
    client = TestClient(app)
    payload = {"case_id": str(case.id), "idempotency_key": "api-approved-revocation"}
    try:
        forbidden = client.post("/v1/executions", json=payload)
        app.dependency_overrides[get_current_principal] = lambda: Principal(
            "user-frank", "frank", frozenset({"athena-administrator"}), {}
        )
        created = client.post("/v1/executions", json=payload)
        listed = client.get("/v1/executions")
    finally:
        app.dependency_overrides.clear()

    assert forbidden.status_code == 403
    assert created.status_code == 201
    assert created.json()["requested_by"] == "frank"
    assert created.json()["status"] == "pending"
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [created.json()["id"]]
