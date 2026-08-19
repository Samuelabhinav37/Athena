import hashlib
from datetime import UTC, datetime

import pytest
from athena.telemetry import (
    SECURITY_EVENT_SCHEMA,
    SecurityEventEnvelope,
    TelemetryResource,
    build_security_event,
)
from pydantic import ValidationError


def _event(**overrides: object) -> SecurityEventEnvelope:
    values = {
        "original_bytes": b'{"event_id":"source-42","action":"login"}',
        "source_type": "json",
        "source_name": "example-siem",
        "source_locator": "collector://example-siem/security",
        "source_format": "application/json",
        "source_event_id": "source-42",
        "event_name": "identity.authentication.succeeded",
        "occurred_at": datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        "received_at": datetime(2026, 8, 19, 12, 0, 1, tzinfo=UTC),
        "severity_number": 9,
        "severity_text": "info",
        "body": {"action": "login", "outcome": "success"},
        "attributes": {"identity.source": "example-siem"},
        "resource": TelemetryResource(
            service_name="athena-ingest",
            service_version="0.1.0",
            deployment_environment="test",
        ),
        "trace_id": "0123456789abcdef0123456789abcdef",
        "span_id": "0123456789abcdef",
    }
    values.update(overrides)
    return build_security_event(**values)  # type: ignore[arg-type]


def test_security_event_is_versioned_otel_aligned_and_preserves_original_provenance() -> None:
    event = _event()

    assert event.schema_url == SECURITY_EVENT_SCHEMA
    assert event.schema_version == "1.0"
    assert event.time_unix_nano == 1_787_140_800_000_000_000
    assert event.observed_time_unix_nano == 1_787_140_801_000_000_000
    assert event.severity_text == "INFO"
    assert event.instrumentation_scope == "athena.security"
    assert event.original_event.content_sha256 == hashlib.sha256(
        b'{"event_id":"source-42","action":"login"}'
    ).hexdigest()
    assert event.original_event.byte_count == 41
    assert event.original_event.source_event_id == "source-42"


def test_original_digest_changes_with_bytes_even_when_normalized_event_is_identical() -> None:
    first = _event(original_bytes=b'{"action":"login"}')
    second = _event(original_bytes=b'{ "action": "login" }')

    assert first.body == second.body
    assert first.original_event.content_sha256 != second.original_event.content_sha256


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"event_name": "Identity Login"}, "lowercase dotted semantic naming"),
        ({"trace_id": "bad", "span_id": "0123456789abcdef"}, "trace_id"),
        ({"trace_id": None}, "supplied together"),
        ({"occurred_at": datetime(2026, 8, 19, 12, 0)}, "timezone"),
        ({"severity_number": 25}, "less than or equal to 24"),
    ],
)
def test_security_event_rejects_nonconformant_otel_fields(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises((ValidationError, ValueError), match=message):
        _event(**overrides)


@pytest.mark.parametrize(
    "unsafe",
    [
        {"authorization": "Bearer secret"},
        {"http.request.header.cookie": "session=secret"},
        {"nested": {"client_secret": "secret"}},
    ],
)
def test_security_event_rejects_sensitive_normalized_keys(unsafe: dict) -> None:
    with pytest.raises(ValidationError, match="forbidden sensitive key"):
        _event(body=unsafe)


def test_security_event_rejects_oversized_original_and_normalized_content() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        _event(original_bytes=b"")
    with pytest.raises(ValueError, match="original event exceeds"):
        _event(original_bytes=b"x" * 1_048_577)
    with pytest.raises(ValidationError, match="normalized event exceeds"):
        _event(body={"message": "x" * 65_536})


def test_original_locator_rejects_credentials_queries_and_fragments() -> None:
    for locator in (
        "https://user:password@example.test/events",
        "https://example.test/events?token=secret",
        "collector://example/events#secret",
    ):
        with pytest.raises(ValidationError, match="source_locator"):
            _event(source_locator=locator)


def test_security_event_contract_is_frozen_and_forbids_unknown_fields() -> None:
    event = _event()
    with pytest.raises(ValidationError, match="frozen"):
        event.event_name = "identity.authentication.failed"
    with pytest.raises(ValidationError, match="Extra inputs"):
        SecurityEventEnvelope.model_validate({**event.model_dump(), "vendor_field": True})
