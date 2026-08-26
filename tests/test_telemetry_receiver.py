import hashlib
import json
from collections.abc import Generator

import pytest
from athena.auth import Principal, get_current_principal
from athena.config import Settings, get_settings
from athena.main import app
from athena.routes.telemetry import SubjectRateLimiter, get_json_rate_limiter
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Generator[TestClient]:
    app.dependency_overrides[get_settings] = lambda: Settings(auth_required=False)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_json_rate_limiter.cache_clear()


def _payload() -> dict:
    return {
        "source_name": "example-siem",
        "source_event_id": "source-42",
        "event_name": "identity.authentication.succeeded",
        "occurred_at": "2026-08-19T12:00:00Z",
        "severity_number": 9,
        "severity_text": "info",
        "body": {"action": "login", "outcome": "success"},
        "attributes": {"identity.source": "example-siem"},
        "resource": {"service_name": "example-idp"},
        "trace_id": "0123456789abcdef0123456789abcdef",
        "span_id": "0123456789abcdef",
    }


def test_json_receiver_requires_authentication_and_administrator_role() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(auth_required=True)
    try:
        with TestClient(app) as unauthenticated:
            missing = unauthenticated.post("/v1/telemetry/events/json", json=_payload())
    finally:
        app.dependency_overrides.clear()
    assert missing.status_code == 401

    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "viewer-id", "alice", frozenset({"athena-viewer"}), {}
    )
    try:
        with TestClient(app) as viewer:
            denied = viewer.post("/v1/telemetry/events/json", json=_payload())
    finally:
        app.dependency_overrides.clear()
    assert denied.status_code == 403


def test_json_receiver_preserves_exact_bytes_and_derives_transport_provenance(
    client: TestClient,
) -> None:
    original = json.dumps(_payload(), separators=(", ", ": ")).encode()
    response = client.post(
        "/v1/telemetry/events/json",
        content=original,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    event = response.json()
    assert event["original_event"]["content_sha256"] == hashlib.sha256(original).hexdigest()
    assert event["original_event"]["byte_count"] == len(original)
    assert event["original_event"]["source_type"] == "json"
    assert event["original_event"]["source_locator"] == "athena://receiver/json"
    assert event["original_event"]["source_format"] == "application/json"
    assert event["body"] == {"action": "login", "outcome": "success"}


@pytest.mark.parametrize(
    ("content", "content_type", "status_code"),
    [
        (b"", "application/json", 400),
        (b"not-json", "application/json", 422),
        (b'{"password":"must-not-echo"}', "application/json", 422),
        (json.dumps(_payload()).encode(), "text/plain", 415),
        (b"x" * 1_048_577, "application/json", 413),
    ],
    ids=["empty", "malformed", "secret-shaped", "wrong-media-type", "oversized"],
)
def test_json_receiver_rejects_invalid_input_without_echoing_content(
    client: TestClient, content: bytes, content_type: str, status_code: int
) -> None:
    response = client.post(
        "/v1/telemetry/events/json",
        content=content,
        headers={"Content-Type": content_type},
    )

    assert response.status_code == status_code
    assert "must-not-echo" not in response.text


def test_json_receiver_rejects_unknown_and_sensitive_normalized_fields(
    client: TestClient,
) -> None:
    unknown = _payload() | {"source_locator": "https://attacker.test/?token=secret"}
    sensitive = _payload() | {"body": {"authorization": "Bearer must-not-echo"}}

    unknown_response = client.post("/v1/telemetry/events/json", json=unknown)
    sensitive_response = client.post("/v1/telemetry/events/json", json=sensitive)

    assert unknown_response.status_code == 422
    assert sensitive_response.status_code == 422
    assert "attacker" not in unknown_response.text
    assert "must-not-echo" not in sensitive_response.text


def test_json_receiver_rate_limits_per_authenticated_subject(client: TestClient) -> None:
    now = [100.0]
    limiter = SubjectRateLimiter(limit=2, window_seconds=60, clock=lambda: now[0])
    app.dependency_overrides[get_json_rate_limiter] = lambda: limiter

    assert client.post("/v1/telemetry/events/json", json=_payload()).status_code == 200
    assert client.post("/v1/telemetry/events/json", json=_payload()).status_code == 200
    limited = client.post("/v1/telemetry/events/json", json=_payload())
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"

    now[0] = 161.0
    assert client.post("/v1/telemetry/events/json", json=_payload()).status_code == 200


def test_rate_limiter_bounds_subject_cardinality() -> None:
    limiter = SubjectRateLimiter(limit=1, max_subjects=2, clock=lambda: 100.0)

    assert limiter.check("subject-1") is None
    assert limiter.check("subject-2") is None
    assert limiter.check("subject-3") is None
    assert len(limiter._requests) == 2
    assert "subject-1" not in limiter._requests
