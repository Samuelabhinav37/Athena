import hashlib
import hmac
import json
import time
from collections.abc import Generator

import pytest
from athena.config import Settings, get_settings
from athena.main import app
from athena.routes.telemetry import get_webhook_replay_cache
from athena.services.webhook import (
    SignedWebhookAdapter,
    WebhookAuthenticationError,
    WebhookReplayCache,
    WebhookReplayError,
)
from fastapi.testclient import TestClient
from pydantic import ValidationError

SECRET = "test-webhook-secret-that-is-at-least-32-characters"
NOW = 1_787_140_800


def _payload(**overrides: object) -> dict:
    event = {
        "source_name": "example-edr",
        "source_event_id": "source-42",
        "event_name": "endpoint.malware.detected",
        "occurred_at": "2026-08-19T12:00:00Z",
        "severity_number": 17,
        "severity_text": "error",
        "body": {"action": "detected", "outcome": "blocked"},
        "attributes": {"security.product": "example-edr"},
        "resource": {"service_name": "example-edr"},
    }
    event.update(overrides)
    return {"schema_version": "1.0", "mapping": "athena.generic.v1", "event": event}


def _body(payload: dict | None = None) -> bytes:
    return json.dumps(payload or _payload(), separators=(",", ":")).encode()


def _signature(body: bytes, delivery_id: str = "delivery-42", timestamp: int = NOW) -> str:
    signed = f"{timestamp}.{delivery_id}.".encode() + body
    digest = hmac.new(SECRET.encode(), signed, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _settings() -> Settings:
    return Settings(webhook_enabled=True, webhook_secret=SECRET, webhook_max_age_seconds=300)


@pytest.fixture
def client() -> Generator[TestClient]:
    app.dependency_overrides[get_settings] = _settings
    cache = WebhookReplayCache(clock=lambda: NOW)
    app.dependency_overrides[get_webhook_replay_cache] = lambda: cache
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_webhook_replay_cache.cache_clear()


def test_webhook_settings_require_disabled_default_and_strong_secret() -> None:
    assert Settings().webhook_enabled is False
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(webhook_enabled=True, webhook_secret="short")


def test_signed_webhook_preserves_exact_request_and_declares_capabilities() -> None:
    body = _body()
    result = SignedWebhookAdapter(
        _settings(), WebhookReplayCache(clock=lambda: NOW), clock=lambda: NOW
    ).normalize(
        original_bytes=body,
        timestamp_header=str(NOW),
        delivery_id="delivery-42",
        signature_header=_signature(body),
    )

    assert result.request_sha256 == hashlib.sha256(body).hexdigest()
    assert result.request_byte_count == len(body)
    assert result.delivery_id == "delivery-42"
    assert result.mapping == "athena.generic.v1"
    assert result.capabilities == (
        "structured_body",
        "scalar_attributes",
        "resource_identity",
        "trace_context",
        "original_request_digest",
    )
    assert result.event.original_event.source_type == "webhook"
    assert result.event.original_event.content_sha256 == hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize(
    ("timestamp", "signature", "delivery_id", "message"),
    [
        (NOW - 301, None, "delivery-42", "freshness"),
        (NOW + 301, None, "delivery-42", "freshness"),
        (NOW, "sha256=" + ("0" * 64), "delivery-42", "signature"),
        (NOW, None, "bad id", "delivery ID"),
    ],
    ids=["stale", "future", "bad-signature", "bad-delivery-id"],
)
def test_signed_webhook_fails_closed_on_authentication_errors(
    timestamp: int, signature: str | None, delivery_id: str, message: str
) -> None:
    body = _body()
    adapter = SignedWebhookAdapter(
        _settings(), WebhookReplayCache(clock=lambda: NOW), clock=lambda: NOW
    )
    supplied_signature = signature or _signature(body, delivery_id, timestamp)

    with pytest.raises(WebhookAuthenticationError, match=message):
        adapter.normalize(
            original_bytes=body,
            timestamp_header=str(timestamp),
            delivery_id=delivery_id,
            signature_header=supplied_signature,
        )


def test_signed_webhook_rejects_noncanonical_timestamp_text() -> None:
    body = _body()
    adapter = SignedWebhookAdapter(
        _settings(), WebhookReplayCache(clock=lambda: NOW), clock=lambda: NOW
    )

    with pytest.raises(WebhookAuthenticationError, match="timestamp"):
        adapter.normalize(
            original_bytes=body,
            timestamp_header=f"+{NOW}",
            delivery_id="delivery-42",
            signature_header=_signature(body),
        )


def test_signed_webhook_replay_cache_is_atomic_bounded_and_expires() -> None:
    now = [float(NOW)]
    cache = WebhookReplayCache(max_entries=2, clock=lambda: now[0])
    cache.check_and_mark("one", NOW + 10)
    with pytest.raises(WebhookReplayError):
        cache.check_and_mark("one", NOW + 10)
    cache.check_and_mark("two", NOW + 10)
    cache.check_and_mark("three", NOW + 10)
    assert len(cache._entries) == 2
    assert "one" not in cache._entries
    now[0] = NOW + 11
    cache.check_and_mark("two", NOW + 20)


def test_webhook_endpoint_is_hidden_when_disabled() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(webhook_enabled=False)
    try:
        with TestClient(app) as disabled:
            response = disabled.post("/v1/telemetry/webhooks/athena-generic", content=_body())
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 404


def test_webhook_endpoint_authenticates_without_bearer_and_rejects_replay(
    client: TestClient,
) -> None:
    body = _body()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-Athena-Webhook-Timestamp": str(timestamp),
        "X-Athena-Webhook-ID": "delivery-42",
        "X-Athena-Webhook-Signature": _signature(body, timestamp=timestamp),
    }
    accepted = client.post(
        "/v1/telemetry/webhooks/athena-generic", content=body, headers=headers
    )
    replayed = client.post(
        "/v1/telemetry/webhooks/athena-generic", content=body, headers=headers
    )

    assert accepted.status_code == 200
    assert accepted.headers["cache-control"] == "no-store"
    assert replayed.status_code == 409


def test_webhook_endpoint_rejects_tampering_and_unknown_mapping_without_echo(
    client: TestClient,
) -> None:
    body = _body()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-Athena-Webhook-Timestamp": str(timestamp),
        "X-Athena-Webhook-ID": "delivery-tampered",
        "X-Athena-Webhook-Signature": _signature(body, "delivery-tampered", timestamp),
    }
    tampered = client.post(
        "/v1/telemetry/webhooks/athena-generic", content=body + b" ", headers=headers
    )
    assert tampered.status_code == 401

    unknown_body = _body(_payload() | {"mapping": "vendor.magic.v9"})
    unknown_headers = {
        **headers,
        "X-Athena-Webhook-ID": "delivery-unknown",
        "X-Athena-Webhook-Signature": _signature(unknown_body, "delivery-unknown", timestamp),
    }
    unknown = client.post(
        "/v1/telemetry/webhooks/athena-generic",
        content=unknown_body,
        headers=unknown_headers,
    )
    assert unknown.status_code == 422
    assert "vendor.magic" not in unknown.text
    assert SECRET not in accepted_text(tampered, unknown)


def accepted_text(*responses: object) -> str:
    return "".join(getattr(response, "text", "") for response in responses)
