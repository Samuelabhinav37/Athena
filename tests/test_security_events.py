import base64
import json
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
from athena.routes import security_events as security_routes
from athena.schemas import SecurityEventCreate
from athena.services.security_agents import canonical_digest
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
