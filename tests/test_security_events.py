import base64
import json
import uuid
from datetime import UTC, datetime

import pytest
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.main import app
from athena.models import (
    Base,
    SecurityAgent,
    SecurityEvent,
    SecurityPolicyVersion,
    Tenant,
    prevent_security_evidence_mutation,
)
from athena.policy.opa import OpaDecision
from athena.routes import security_events as security_routes
from athena.schemas import SecurityEventCreate
from athena.services.security_agents import AgentActionPolicyError, canonical_digest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def security_client(monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    policy_key = Ed25519PrivateKey.generate()
    policy_public_pem = policy_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    factory = sessionmaker(bind=engine, expire_on_commit=False, info={"tenant_id": "test-tenant"})
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    with factory() as session:
        session.add(
            Tenant(
                id="test-tenant",
                display_name="Test Tenant",
                approval_reference="approved-test-tenant",
                authorized_by="security@example.com",
                approved_at=now,
                inventory_sha256="0" * 64,
            )
        )
        session.commit()

    def session_dependency():
        with factory() as session:
            yield session

    settings = Settings(
        database_url="sqlite://",
        auth_required=False,
        system_tenant_id="test-tenant",
        security_agents_enabled=True,
        security_agent_token_secret="a" * 32,
        security_policy_public_key_pem=policy_public_pem,
        api_worker_count=1,
        api_replica_count=1,
    )
    app.dependency_overrides[get_db_session] = session_dependency
    app.dependency_overrides[get_settings] = lambda: settings
    monkeypatch.setattr(security_routes, "get_session_factory", lambda _tenant: factory)
    try:
        yield TestClient(app), factory, policy_key
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_agent_enrollment_token_event_and_policy_flow(security_client) -> None:
    client, factory, policy_key = security_client
    enrollment = client.post(
        "/v1/security/agents",
        json={"external_id": "chrome-device-1", "agent_type": "moat", "display_name": "Moat"},
    )
    assert enrollment.status_code == 201
    enrollment_body = enrollment.json()
    assert enrollment_body["enrollment_secret"]

    exchange = client.post(
        "/v1/security/agent-token",
        json={
            "tenant_id": "test-tenant",
            "agent_id": enrollment_body["id"],
            "enrollment_secret": enrollment_body["enrollment_secret"],
        },
    )
    assert exchange.status_code == 200
    agent_headers = {"Authorization": f"Bearer {exchange.json()['access_token']}"}

    event_payload = {
        "source_event_id": "moat-event-1",
        "occurred_at": "2026-08-28T12:00:00Z",
        "action": "blocked",
        "severity": "high",
        "rule_id": "phishing-domain-42",
        "policy_version": "2026.08.28.1",
        "subject_pseudonym": "user-sha256",
        "target_indicator": "malicious.example",
        "evidence": {"ruleset": "phishing", "match_type": "domain"},
    }
    created = client.post("/v1/security/events", headers=agent_headers, json=event_payload)
    assert created.status_code == 201
    replay = client.post("/v1/security/events", headers=agent_headers, json=event_payload)
    assert replay.status_code == 201
    assert replay.json()["id"] == created.json()["id"]

    policy = {"blocked_domains": ["malicious.example"], "default_action": "block"}
    signature = base64.b64encode(
        policy_key.sign(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode())
    ).decode()
    published = client.post(
        "/v1/security/policies",
        json={
            "agent_type": "moat",
            "version": "2026.08.28.1",
            "policy": policy,
            "policy_digest": canonical_digest(policy),
            "signature": signature,
            "signing_key_id": "athena-policy-key-1",
        },
    )
    assert published.status_code == 201
    latest = client.get("/v1/security/policies/latest", headers=agent_headers)
    assert latest.status_code == 200
    assert latest.json()["policy"] == policy

    events = client.get("/v1/security/events")
    assert events.status_code == 200
    assert len(events.json()) == 1
    with factory() as session:
        assert session.scalar(select(SecurityAgent)) is not None


def test_security_event_reads_are_tenant_scoped_without_database_rls(security_client) -> None:
    client, factory, _policy_key = security_client
    other_tenant_id = "other-tenant"
    with factory.begin() as session:
        session.add(
            Tenant(
                id=other_tenant_id,
                display_name="Other Tenant",
                approval_reference="approved-other-tenant",
                authorized_by="security@example.com",
                approved_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                inventory_sha256="1" * 64,
            )
        )
    other_factory = sessionmaker(
        bind=factory.kw["bind"], expire_on_commit=False, info={"tenant_id": other_tenant_id}
    )
    with other_factory.begin() as session:
        agent = SecurityAgent(
            id=uuid.uuid4(),
            external_id="foreign-agent",
            agent_type="moat",
            display_name="Foreign Agent",
            credential_salt="salt",
            credential_digest="digest",
            enrolled_by="other-admin",
        )
        session.add(agent)
        session.flush()
        session.add(
            SecurityEvent(
                agent_id=agent.id,
                source_event_id="foreign-event",
                occurred_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                action="blocked",
                severity="high",
                rule_id="foreign-rule",
                evidence={},
                evidence_digest="2" * 64,
            )
        )

    assert client.get("/v1/security/events").json() == []
    assert client.get("/v1/security/agents").json() == []


def test_security_event_rejects_sensitive_or_full_url_evidence(security_client) -> None:
    with pytest.raises(ValueError, match="minimized domain"):
        SecurityEventCreate.model_validate(
            {
            "source_event_id": "event-1",
            "occurred_at": "2026-08-28T12:00:00Z",
            "action": "blocked",
            "severity": "high",
            "rule_id": "rule-1",
            "target_indicator": "https://malicious.example/path",
            "evidence": {"email_body": "sensitive"},
            }
        )
    with pytest.raises(ValueError, match="forbidden sensitive"):
        SecurityEventCreate.model_validate(
            {
                "source_event_id": "event-2",
                "occurred_at": "2026-08-28T12:00:00Z",
                "action": "blocked",
                "severity": "high",
                "rule_id": "rule-1",
                "target_indicator": "malicious.example",
                "evidence": {"email_body": "sensitive"},
            }
        )


@pytest.mark.parametrize("model_type", [SecurityAgent, SecurityEvent, SecurityPolicyVersion])
def test_security_domain_models_are_append_only(model_type) -> None:
    assert event.contains(model_type, "before_update", prevent_security_evidence_mutation)
    assert event.contains(model_type, "before_delete", prevent_security_evidence_mutation)


def _enroll_and_authenticate(
    client: TestClient, agent_type: str, external_id: str
) -> dict[str, str]:
    enrollment = client.post(
        "/v1/security/agents",
        json={"external_id": external_id, "agent_type": agent_type, "display_name": external_id},
    )
    assert enrollment.status_code == 201
    body = enrollment.json()
    exchange = client.post(
        "/v1/security/agent-token",
        json={
            "tenant_id": "test-tenant",
            "agent_id": body["id"],
            "enrollment_secret": body["enrollment_secret"],
        },
    )
    assert exchange.status_code == 200
    return {"Authorization": f"Bearer {exchange.json()['access_token']}"}


def test_cross_product_correlation_surfaces_an_indicator_seen_by_both_agent_types(
    security_client,
) -> None:
    client, _factory, _policy_key = security_client
    moat_headers = _enroll_and_authenticate(client, "moat", "moat-device-1")
    clutter_headers = _enroll_and_authenticate(client, "clutter", "clutter-mailbox-1")

    moat_event = {
        "source_event_id": "moat-evt-1",
        "occurred_at": "2026-08-28T12:00:00Z",
        "action": "blocked",
        "severity": "high",
        "rule_id": "phishing-domain-42",
        "target_indicator": "shared-evil.example",
        "evidence": {},
    }
    clutter_event = {
        "source_event_id": "clutter-evt-1",
        "occurred_at": "2026-08-28T13:00:00Z",
        "action": "warned",
        "severity": "critical",
        "rule_id": "threat-signal:lookalike-domain",
        "target_indicator": "shared-evil.example",
        "evidence": {"brand": "example"},
    }
    moat_response = client.post("/v1/security/events", headers=moat_headers, json=moat_event)
    assert moat_response.status_code == 201
    clutter_response = client.post(
        "/v1/security/events", headers=clutter_headers, json=clutter_event
    )
    assert clutter_response.status_code == 201

    # A single-agent-type indicator should never appear in the correlation
    # list -- the overwhelmingly common case, and the negative case this
    # feature exists to filter out.
    moat_only_event = {
        **moat_event,
        "source_event_id": "moat-evt-2",
        "target_indicator": "moat-only.example",
    }
    moat_only_response = client.post(
        "/v1/security/events", headers=moat_headers, json=moat_only_event
    )
    assert moat_only_response.status_code == 201

    correlations = client.get("/v1/security/events/correlations")
    assert correlations.status_code == 200
    body = correlations.json()
    assert len(body) == 1
    entry = body[0]
    assert entry["target_indicator"] == "shared-evil.example"
    assert sorted(entry["agent_types"]) == ["clutter", "moat"]
    assert entry["event_count"] == 2
    # critical (clutter) outranks high (moat) -- the whole reason severity
    # is ranked explicitly rather than sorted as a plain string.
    assert entry["highest_severity"] == "critical"
    assert sorted(entry["rule_ids"]) == ["phishing-domain-42", "threat-signal:lookalike-domain"]


def test_cross_product_correlation_respects_the_window(security_client) -> None:
    client, _factory, _policy_key = security_client
    moat_headers = _enroll_and_authenticate(client, "moat", "moat-device-1")
    clutter_headers = _enroll_and_authenticate(client, "clutter", "clutter-mailbox-1")

    old_shared = {
        "source_event_id": "old-1",
        "occurred_at": "2020-01-01T00:00:00Z",
        "action": "blocked",
        "severity": "high",
        "rule_id": "r1",
        "target_indicator": "stale-shared.example",
        "evidence": {},
    }
    old_shared_response = client.post("/v1/security/events", headers=moat_headers, json=old_shared)
    assert old_shared_response.status_code == 201
    assert (
        client.post(
            "/v1/security/events",
            headers=clutter_headers,
            json={**old_shared, "source_event_id": "old-2", "action": "warned"},
        ).status_code
        == 201
    )

    correlations = client.get("/v1/security/events/correlations", params={"window_days": 30})
    assert correlations.status_code == 200
    assert correlations.json() == []


def test_override_event_denied_by_policy_is_rejected(
    security_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _factory, _policy_key = security_client
    headers = _enroll_and_authenticate(client, "moat", "moat-device-1")

    def deny(_settings, _action, _reason):
        raise AgentActionPolicyError(
            "denied",
            [{"code": "UNJUSTIFIED_OVERRIDE", "severity": "medium", "message": "too short"}],
        )

    monkeypatch.setattr(security_routes, "evaluate_agent_action", deny)
    response = client.post(
        "/v1/security/events",
        headers=headers,
        json={
            "source_event_id": "override-1",
            "occurred_at": "2026-08-28T12:00:00Z",
            "action": "allowed_override",
            "severity": "low",
            "rule_id": "athena-policy:evil.example",
            "target_indicator": "evil.example",
            "evidence": {"override_reason": "no"},
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"]["violations"][0]["code"] == "UNJUSTIFIED_OVERRIDE"


def test_override_event_allowed_by_policy_is_ingested(
    security_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _factory, _policy_key = security_client
    headers = _enroll_and_authenticate(client, "moat", "moat-device-1")

    def allow(_settings, action, reason):
        assert action == "allowed_override"
        assert reason == "This vendor domain is a known false positive, verified with IT"
        return OpaDecision(allow=True, violations=[])

    monkeypatch.setattr(security_routes, "evaluate_agent_action", allow)
    response = client.post(
        "/v1/security/events",
        headers=headers,
        json={
            "source_event_id": "override-2",
            "occurred_at": "2026-08-28T12:00:00Z",
            "action": "allowed_override",
            "severity": "low",
            "rule_id": "athena-policy:evil.example",
            "target_indicator": "evil.example",
            "evidence": {
                "override_reason": "This vendor domain is a known false positive, verified with IT"
            },
        },
    )
    assert response.status_code == 201


def test_override_event_with_opa_unreachable_returns_503(
    security_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _factory, _policy_key = security_client
    headers = _enroll_and_authenticate(client, "moat", "moat-device-1")

    def unreachable(_settings, _action, _reason):
        raise AgentActionPolicyError("OPA request failed")

    monkeypatch.setattr(security_routes, "evaluate_agent_action", unreachable)
    response = client.post(
        "/v1/security/events",
        headers=headers,
        json={
            "source_event_id": "override-3",
            "occurred_at": "2026-08-28T12:00:00Z",
            "action": "allowed_override",
            "severity": "low",
            "rule_id": "athena-policy:evil.example",
            "target_indicator": "evil.example",
            "evidence": {"override_reason": "long enough reason to pass validation"},
        },
    )
    assert response.status_code == 503


def test_non_override_events_never_reach_the_policy_engine(
    security_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _factory, _policy_key = security_client
    headers = _enroll_and_authenticate(client, "moat", "moat-device-1")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("evaluate_agent_action should not be called for a non-override action")

    monkeypatch.setattr(security_routes, "evaluate_agent_action", fail_if_called)
    response = client.post(
        "/v1/security/events",
        headers=headers,
        json={
            "source_event_id": "blocked-no-opa",
            "occurred_at": "2026-08-28T12:00:00Z",
            "action": "blocked",
            "severity": "high",
            "rule_id": "phishing-domain-42",
            "target_indicator": "evil.example",
            "evidence": {},
        },
    )
    assert response.status_code == 201
