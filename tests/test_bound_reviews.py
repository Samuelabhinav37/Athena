import uuid
from datetime import UTC, datetime, timedelta

import pytest
from athena.auth import Principal, get_current_principal
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.main import app
from athena.models import (
    AccessGrant,
    ConnectorCheckpoint,
    EffectiveEntitlement,
    Identity,
    PolicyEvaluation,
    ReviewCase,
    ReviewDecision,
    Reviewer,
    ReviewStatus,
    RiskFinding,
)
from athena.services.bound_reviews import BoundReviewService, digest
from athena.services.risk_analytics import RiskAnalyticsService
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError
from test_risk_analytics import risk_session as _risk_session

risk_session = _risk_session


def actor(name, role="athena-reviewer", issuer="https://idp.test"):
    return Principal(f"user-{name}", name, frozenset({role}), {"iss": issuer})


@pytest.fixture
def bound(risk_session):
    settings = Settings(database_url="sqlite://", oidc_issuer="https://idp.test")
    service = BoundReviewService(risk_session, settings)
    alice = risk_session.scalar(select(Identity).where(Identity.username == "alice"))
    bob = risk_session.scalar(select(Identity).where(Identity.username == "bob"))
    charlie = risk_session.scalar(select(Identity).where(Identity.username == "charlie"))
    admin = actor("admin", "athena-administrator")
    owner = service.register(charlie.id, admin, "Reviewed synthetic reviewer eligibility")
    operator = service.register(bob.id, admin, "Reviewed synthetic operator eligibility")
    entitlement = risk_session.scalar(
        select(EffectiveEntitlement).where(
            EffectiveEntitlement.identity_id == alice.id,
        )
    )
    entitlement.grant.source = "azure_rbac"
    entitlement.grant.source_metadata = {
        "source_assignment_id": "synthetic-assignment",
        "subscription_id": "synthetic-scope",
        "lineage_complete": False,
    }
    risk_session.commit()
    result = RiskAnalyticsService(risk_session).assess(alice)
    finding = risk_session.scalar(
        select(RiskFinding).where(
            RiskFinding.assessment_id == result.assessment_id,
            RiskFinding.entitlement_id == entitlement.id,
        )
    )
    return service, alice, finding, owner, operator, admin


def opened(bound, action=ReviewDecision.REVOKE, goal="assignment_removed"):
    service, alice, finding, owner, _, admin = bound
    case = service.open(alice.id, finding.id, None, action, goal, 7, admin)
    return service.assign(case.id, case.revision, owner.id, admin, "Assign eligible reviewer")


def test_api_exact_target_assignment_and_immutable_actor(bound, risk_session):
    service, alice, finding, owner, _, admin = bound
    app.dependency_overrides[get_db_session] = lambda: risk_session
    app.dependency_overrides[get_settings] = lambda: service.settings
    app.dependency_overrides[get_current_principal] = lambda: admin
    try:
        client = TestClient(app)
        response = client.post(
            "/v1/reviews",
            json={
                "identity_id": str(alice.id),
                "finding_id": str(finding.id),
                "proposed_action": "revoke",
                "closure_goal": "assignment_removed",
            },
        )
        assert response.status_code == 201
        case = response.json()
        assigned = client.post(
            f"/v1/reviews/{case['id']}/assign",
            json={
                "owner_id": str(owner.id),
                "revision": case["revision"],
                "reason": "Assign reviewer",
            },
        )
        assert assigned.status_code == 200
        app.dependency_overrides[get_current_principal] = lambda: Principal(
            owner.subject,
            "renamed-charlie",
            frozenset({"athena-reviewer"}),
            {"iss": owner.issuer},
        )
        decided = client.post(
            f"/v1/reviews/{case['id']}/decide",
            json={
                "decision": "revoke",
                "revision": assigned.json()["revision"],
                "reason": "Approved removal of the exact assignment",
            },
        )
        assert decided.status_code == 200
        assert (
            decided.json()["events"][-1]["evidence_snapshot"]["actor"]["subject"] == owner.subject
        )
        assert decided.json()["events"][-1]["execution_status"] == "pending"
        assert risk_session.get(EffectiveEntitlement, finding.entitlement_id).active
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("problem", ["subject", "issuer", "inactive", "revision", "target", "self"])
def test_approval_rejects_invalid_owner_or_target(bound, risk_session, problem):
    service, alice, finding, owner, _, admin = bound
    case = opened(bound)
    principal = actor("charlie")
    revision = case.revision
    if problem == "subject":
        principal = Principal("recycled-subject", "charlie", principal.roles, principal.claims)
    elif problem == "issuer":
        principal = actor("charlie", issuer="https://other.test")
    elif problem == "inactive":
        service.set_eligible(owner.id, False, admin, "Reviewer departed the organization")
    elif problem == "revision":
        revision -= 1
    elif problem == "target":
        grant = risk_session.get(EffectiveEntitlement, finding.entitlement_id).grant
        grant.source_metadata = {**grant.source_metadata, "source_assignment_id": "changed"}
        risk_session.commit()
    else:
        self_owner = service.register(alice.id, admin, "Synthetic self-review scenario")
        service.assign(
            case.id, case.revision, self_owner.id, admin, "Attempt self-review assignment"
        )
        revision = case.revision
        principal = actor("alice")
    with pytest.raises(ValueError):
        service.decide(
            case.id, revision, ReviewDecision.REVOKE, principal, "Attempt unsafe approval"
        )
    risk_session.rollback()
    assert risk_session.get(ReviewCase, case.id).status == ReviewStatus.IN_REVIEW


def test_cross_tenant_lookup_and_legacy_rebinding_fail_closed(bound, risk_session):
    service, *_ = bound
    case = opened(bound)
    risk_session.info["tenant_id"] = "another-tenant"
    with pytest.raises(ValueError, match="unavailable"):
        service.locked(case.id, case.revision)
    risk_session.info["tenant_id"] = "test-tenant"
    old = dict(case.target_snapshot)
    case.target_snapshot = {**old, "proposed_action": "retain"}
    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()
    owner = risk_session.get(Reviewer, bound[3].id)
    owner.subject = "replacement"
    with pytest.raises(ValueError, match="immutable"):
        risk_session.commit()
    risk_session.rollback()


def test_policy_only_review_and_distinct_targets(bound, risk_session):
    service, alice, finding, _, _, admin = bound
    policy = risk_session.scalar(
        select(PolicyEvaluation).where(
            PolicyEvaluation.entitlement_id == finding.entitlement_id,
        )
    )
    case = service.open(
        alice.id, None, policy.id, ReviewDecision.RETAIN, "record_decision", 7, admin
    )
    assert case.risk_assessment_id is None
    assert case.policy_evaluation_id == policy.id
    duplicate = service.open(
        alice.id, None, policy.id, ReviewDecision.RETAIN, "record_decision", 7, admin
    )
    assert duplicate.id == case.id
    different = service.open(
        alice.id, finding.id, None, ReviewDecision.REVOKE, "assignment_removed", 7, admin
    )
    assert different.id != case.id


def test_operator_completion_does_not_mean_verified_removal(bound, risk_session):
    service, _, finding, _, operator, admin = bound
    case = opened(bound)
    service.decide(
        case.id, case.revision, ReviewDecision.REVOKE, actor("charlie"), "Approve exact removal"
    )
    service.fulfill(
        case.id, case.revision, operator.id, admin, "Remove this exact assignment", False, 7
    )
    service.fulfill(
        case.id, case.revision, None, actor("bob"), "Operator reports completed removal", True, 7
    )
    service.verify(case.id, case.revision, admin)
    assert (
        service.latest(case, "verification_recorded").evidence_snapshot["outcome"]
        == "collection_required"
    )
    checkpoint = ConnectorCheckpoint(
        connector="azure_rbac",
        scope="synthetic-scope",
        fingerprint="a" * 64,
        endpoint_cache={},
        observed_at=datetime.now(UTC),
    )
    risk_session.add(checkpoint)
    risk_session.commit()
    service.verify(case.id, case.revision, admin)
    assert (
        service.latest(case, "verification_recorded").evidence_snapshot["outcome"]
        == "still_present"
    )
    entitlement = risk_session.get(EffectiveEntitlement, finding.entitlement_id)
    entitlement.active = False
    entitlement.grant.revoked_at = datetime.now(UTC)
    checkpoint.observed_at = datetime.now(UTC)
    checkpoint.fingerprint = "b" * 64
    risk_session.commit()
    service.verify(case.id, case.revision, admin)
    assert service.latest(case, "verification_recorded").evidence_snapshot["outcome"] == "verified"
    packet = service.report(case.id)
    assert packet["digest"] == digest(packet["packet"])
    assert sum(e["action"] == "verification_recorded" for e in packet["packet"]["events"]) == 3


def test_stale_and_future_evidence_are_not_approvable(bound):
    service = bound[0]
    for observed in (datetime.now(UTC) - timedelta(days=2), datetime.now(UTC) + timedelta(days=1)):
        with pytest.raises(ValueError, match="not current"):
            service._fresh(observed)


def test_case_revision_prevents_lost_update(bound, risk_session):
    case = opened(bound)
    with Session(bind=risk_session.get_bind(), info={"tenant_id": "test-tenant"}) as other:
        stale = other.get(ReviewCase, case.id)
        case.owner = "new display"
        risk_session.commit()
        stale.owner = "concurrent display"
        with pytest.raises(StaleDataError):
            other.commit()


def test_unknown_and_other_tenant_reviewer_cannot_be_assigned(bound):
    service = bound[0]
    case = opened(bound)
    with pytest.raises(ValueError):
        service.assign(
            case.id, case.revision, uuid.uuid4(), bound[5], "Unknown reviewer assignment"
        )


def test_cancel_allows_fresh_evidence_without_rewriting_old_review(bound):
    service = bound[0]
    case = opened(bound)
    snapshot = dict(case.target_snapshot)
    service.cancel(case.id, case.revision, bound[5], "Cancel stale evidence for reassessment")
    fresh = opened(bound)
    assert fresh.id != case.id
    assert case.target_snapshot == snapshot
    assert case.status == ReviewStatus.CANCELLED


@pytest.mark.parametrize("goal", ["assignment_removed", "no_supported_paths"])
def test_permission_disappearance_is_not_proof_of_closure(bound, risk_session, goal):
    service, _, finding, _, operator, admin = bound
    case = opened(bound, goal=goal)
    service.decide(
        case.id, case.revision, ReviewDecision.REVOKE, actor("charlie"), "Approve removal"
    )
    service.fulfill(case.id, case.revision, operator.id, admin, "Assign manual removal", False, 7)
    service.fulfill(
        case.id, case.revision, None, actor("bob"), "Operator completed correction", True, 7
    )
    entitlement = risk_session.get(EffectiveEntitlement, finding.entitlement_id)
    entitlement.active = False
    entitlement.grant.revoked_at = datetime.now(UTC)
    if goal == "assignment_removed":
        risk_session.add(
            AccessGrant(
                source="azure_rbac",
                external_id="changed-role-action",
                subject_type=entitlement.grant.subject_type,
                identity=entitlement.grant.identity,
                permission=entitlement.permission,
                granted_at=datetime.now(UTC),
                source_metadata=dict(entitlement.grant.source_metadata),
            )
        )
    risk_session.add(
        ConnectorCheckpoint(
            connector="azure_rbac",
            scope="synthetic-scope",
            fingerprint="c" * 64,
            endpoint_cache={},
            observed_at=datetime.now(UTC),
        )
    )
    risk_session.commit()
    service.verify(case.id, case.revision, admin)
    outcome = service.latest(case, "verification_recorded").evidence_snapshot["outcome"]
    assert outcome == ("still_present" if goal == "assignment_removed" else "insufficient_coverage")
    service.fulfill(
        case.id, case.revision, operator.id, admin, "Retry incomplete correction", False, 7
    )
    with pytest.raises(ValueError, match="completion"):
        service.verify(case.id, case.revision, admin)


def completed_case(bound):
    service, _, _, _, operator, admin = bound
    case = opened(bound)
    service.decide(
        case.id, case.revision, ReviewDecision.REVOKE, actor("charlie"), "Approve removal"
    )
    service.fulfill(case.id, case.revision, operator.id, admin, "Assign manual removal", False, 7)
    service.fulfill(
        case.id, case.revision, None, actor("bob"), "Operator completed removal", True, 7
    )
    return case


@pytest.mark.parametrize("approved", [False, True])
def test_recollection_failure_preserves_completion_and_sanitizes_errors(
    bound, risk_session, monkeypatch, approved
):
    from athena.models import ConnectorScopeBinding, MonitoringRun
    from athena.services.review_collection import ReviewCollectionService

    case = completed_case(bound)
    settings = bound[0].settings.model_copy(
        update={
            "azure_enabled": True,
            "azure_tenant_id": "synthetic-tenant",
            "azure_subscription_id": "synthetic-scope",
        }
    )
    if approved:
        risk_session.add(
            ConnectorScopeBinding(
                connector="azure",
                scope="synthetic-tenant/synthetic-scope",
                approval_reference="test",
                approved_by="test",
                approved_at=datetime.now(UTC),
            )
        )
        risk_session.commit()
    calls = []

    def fail(_settings):
        calls.append(True)
        raise RuntimeError("sensitive-provider-response")

    monkeypatch.setattr("athena.services.review_collection.AzureCollector", fail)
    service = ReviewCollectionService(risk_session, settings)
    revision = case.revision
    for _ in range(2):
        with pytest.raises(ValueError, match="Completion remains saved"):
            service.collect_and_verify(case.id, revision, bound[5])
    assert len(calls) == (2 if approved else 0)
    assert case.revision == revision
    assert service.latest(case, "operator_completed") is not None
    assert service.latest(case, "verification_recorded") is None
    runs = list(risk_session.scalars(select(MonitoringRun)))
    assert len(runs) == 1
    assert runs[0].attempt_count == 2
    assert "sensitive-provider-response" not in runs[0].error


def test_recollection_replay_after_interruption_does_not_refetch(bound, risk_session, monkeypatch):
    from types import SimpleNamespace

    from athena.models import ConnectorScopeBinding
    from athena.services.review_collection import ReviewCollectionService

    case = completed_case(bound)
    settings = bound[0].settings.model_copy(
        update={
            "azure_enabled": True,
            "azure_tenant_id": "synthetic-tenant",
            "azure_subscription_id": "synthetic-scope",
        }
    )
    risk_session.add(
        ConnectorScopeBinding(
            connector="azure",
            scope="synthetic-tenant/synthetic-scope",
            approval_reference="test",
            approved_by="test",
            approved_at=datetime.now(UTC),
        )
    )
    risk_session.commit()
    calls = []

    class Collector:
        def __init__(self, settings):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def collect(self):
            calls.append(True)
            return SimpleNamespace(tenant_id="synthetic-tenant", subscription_id="synthetic-scope")

    def sync(self, snapshot):
        risk_session.add(
            ConnectorCheckpoint(
                connector="azure_rbac",
                scope="synthetic-scope",
                fingerprint="a" * 64,
                endpoint_cache={},
                observed_at=datetime.now(UTC),
            )
        )
        risk_session.commit()

    monkeypatch.setattr("athena.services.review_collection.AzureCollector", Collector)
    monkeypatch.setattr("athena.services.review_collection.AzureSyncService.sync", sync)
    service = ReviewCollectionService(risk_session, settings)
    original_verify = service.verify

    def interrupted(*args):
        raise RuntimeError("request interrupted before verification")

    monkeypatch.setattr(service, "verify", interrupted)
    revision = case.revision
    with pytest.raises(RuntimeError, match="interrupted"):
        service.collect_and_verify(case.id, revision, bound[5])
    monkeypatch.setattr(service, "verify", original_verify)
    service.collect_and_verify(case.id, revision, bound[5])
    assert len(calls) == 1
    assert (
        service.latest(case, "verification_recorded").evidence_snapshot["outcome"]
        == "still_present"
    )


def test_completion_api_queues_without_calling_collector(bound, risk_session, monkeypatch):
    def unexpected(*args):
        pytest.fail("The API must not call a collector")

    monkeypatch.setattr("athena.services.review_collection.AzureCollector", unexpected)
    service, _, _, _, operator, admin = bound
    case = opened(bound)
    service.decide(
        case.id, case.revision, ReviewDecision.REVOKE, actor("charlie"), "Approve removal"
    )
    service.fulfill(case.id, case.revision, operator.id, admin, "Assign manual removal", False, 7)
    app.dependency_overrides[get_db_session] = lambda: risk_session
    app.dependency_overrides[get_settings] = lambda: service.settings
    app.dependency_overrides[get_current_principal] = lambda: actor("bob")
    try:
        response = TestClient(app).post(
            f"/v1/reviews/{case.id}/fulfillment",
            json={"revision": case.revision, "complete": True, "reason": "Manual removal finished"},
        )
        assert response.status_code == 202
        assert service.latest(case, "operator_completed") is not None
        assert service.latest(case, "verification_recorded") is None
    finally:
        app.dependency_overrides.clear()


def test_worker_backoff_budget_and_durable_completion(bound, risk_session):
    from athena.models import MonitoringRun
    from athena.services.review_worker import ReviewRetryWorker

    case = completed_case(bound)
    now = datetime.now(UTC)
    worker = ReviewRetryWorker(risk_session, bound[0].settings, clock=lambda: now)
    assert worker.run_once()["failed"] == 1
    assert worker.run_once()["attempted"] == 0
    for _ in range(4):
        now += timedelta(hours=2)
        assert worker.run_once()["failed"] == 1
    now += timedelta(days=1)
    assert worker.run_once()["attempted"] == 0
    assert sum(run.attempt_count for run in risk_session.scalars(select(MonitoringRun))) == 5
    assert bound[0].latest(case, "operator_completed") is not None
    assert bound[0].latest(case, "verification_recorded") is None


def test_worker_stops_on_outcome_and_uses_service_attribution(bound, risk_session, monkeypatch):
    from athena.services.review_worker import ReviewRetryWorker

    case = completed_case(bound)
    worker = ReviewRetryWorker(risk_session, bound[0].settings)
    # Exercise real verification and event attribution using recorded evidence;
    # the collector itself is covered by the recollection tests above.
    monkeypatch.setattr(worker.service, "collect_and_verify", worker.service.verify)
    result = worker.run_once()
    assert result["verification_recorded"] == 1
    event = bound[0].latest(case, "verification_recorded")
    assert event.evidence_snapshot["actor"]["kind"] == "service"
    assert event.evidence_snapshot["actor"]["issuer"] == "urn:athena:internal-worker"
    # collection_required remains retryable; an observed provider outcome stops retries.
    risk_session.add(
        ConnectorCheckpoint(
            connector="azure_rbac",
            scope="synthetic-scope",
            fingerprint="a" * 64,
            endpoint_cache={},
            observed_at=datetime.now(UTC),
        )
    )
    risk_session.commit()
    assert worker.run_once()["verification_recorded"] == 1
    assert worker.run_once()["attempted"] == 0


def test_worker_cannot_scan_another_tenants_pending_completion(bound, risk_session):
    from athena.services.review_worker import ReviewRetryWorker

    completed_case(bound)
    with Session(bind=risk_session.get_bind(), info={"tenant_id": "other-tenant"}) as other:
        assert ReviewRetryWorker(other, bound[0].settings).run_once()["attempted"] == 0


def test_worker_respects_live_collection_lease(bound, risk_session):
    from athena.models import MonitoringRun, MonitoringStatus
    from athena.services.review_worker import ReviewRetryWorker

    case = completed_case(bound)
    completion = bound[0].latest(case, "operator_completed")
    now = datetime.now(UTC)
    risk_session.add(
        MonitoringRun(
            schedule_key=f"review-collection:{completion.id}:{case.revision}:test",
            status=MonitoringStatus.RUNNING,
            attempt_count=1,
            requested_by="test",
            started_at=now,
            lease_expires_at=now + timedelta(minutes=15),
        )
    )
    risk_session.commit()
    worker = ReviewRetryWorker(risk_session, bound[0].settings, clock=lambda: now)
    assert worker.run_once()["attempted"] == 0
    now += timedelta(minutes=16)
    assert worker.ready(case)


def test_exhausted_work_can_be_requeued_without_rewriting_evidence(bound, risk_session):
    from athena.services.review_worker import ReviewRetryWorker

    case = completed_case(bound)
    service = bound[0]
    now = datetime.now(UTC)
    worker = ReviewRetryWorker(risk_session, service.settings, clock=lambda: now)
    for _ in range(5):
        worker.run_once()
        now += timedelta(hours=2)
    assert worker.collection_status(case)["state"] == "exhausted"
    original = [(event.id, dict(event.evidence_snapshot)) for event in case.events]
    service.request_verification(case.id, case.revision, bound[5])
    status = worker.collection_status(case)
    assert status["state"] == "queued"
    assert status["attempts"] == 0
    assert original == [(event.id, event.evidence_snapshot) for event in case.events[:-1]]
    worker.run_once()
    status = worker.collection_status(case)
    assert status["attempts"] == 1


def test_async_retry_api_and_status_preserve_revision_guards(bound, risk_session, monkeypatch):
    case = completed_case(bound)
    service = bound[0]

    def unexpected(*args):
        pytest.fail("HTTP requests must not perform collection")

    monkeypatch.setattr("athena.services.review_collection.AzureCollector", unexpected)
    app.dependency_overrides[get_db_session] = lambda: risk_session
    app.dependency_overrides[get_settings] = lambda: service.settings
    app.dependency_overrides[get_current_principal] = lambda: bound[5]
    try:
        client = TestClient(app)
        revision = case.revision
        response = client.post(f"/v1/reviews/{case.id}/verify", json={"revision": revision})
        assert response.status_code == 202
        assert response.json()["revision"] > revision
        status = client.get(f"/v1/reviews/{case.id}/collection-status")
        assert status.status_code == 200
        assert status.json()["state"] == "queued"
        assert (
            client.post(f"/v1/reviews/{case.id}/verify", json={"revision": revision}).status_code
            == 409
        )
        assert client.get(f"/v1/reviews/{uuid.uuid4()}/collection-status").status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_new_request_supersedes_a_recorded_outcome(bound, risk_session):
    from athena.services.review_worker import ReviewRetryWorker

    case = completed_case(bound)
    service = bound[0]
    risk_session.add(
        ConnectorCheckpoint(
            connector="azure_rbac",
            scope="synthetic-scope",
            fingerprint="a" * 64,
            endpoint_cache={},
            observed_at=datetime.now(UTC),
        )
    )
    risk_session.commit()
    service.verify(case.id, case.revision, bound[5])
    worker = ReviewRetryWorker(risk_session, service.settings)
    assert worker.collection_status(case)["outcome"] == "still_present"
    service.request_verification(case.id, case.revision, bound[5])
    assert worker.collection_status(case)["state"] == "queued"
    assert worker.collection_status(case)["outcome"] is None
