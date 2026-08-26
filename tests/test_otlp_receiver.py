import hashlib
import json
from collections.abc import Generator

import pytest
from athena.config import Settings, get_settings
from athena.main import app
from athena.routes.telemetry import get_json_rate_limiter
from athena.services.otlp import OTLPJSONLogAdapter, OTLPMappingError
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Generator[TestClient]:
    app.dependency_overrides[get_settings] = lambda: Settings(auth_required=False)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_json_rate_limiter.cache_clear()


def _any(value: object) -> dict:
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    raise AssertionError("unsupported fixture value")


def _attributes(**values: object) -> list[dict]:
    return [{"key": key, "value": _any(value)} for key, value in values.items()]


def _request(record: dict | None = None) -> dict:
    log_record = record or {
        "timeUnixNano": "1787140800000000123",
        "observedTimeUnixNano": "1787140801000000456",
        "severityNumber": 17,
        "severityText": "ERROR",
        "eventName": "identity.authentication.failed",
        "body": {"kvlistValue": {"values": _attributes(action="login", outcome="failure")}},
        "attributes": _attributes(**{"event.id": "source-42", "identity.source": "idp"}),
        "traceId": "0123456789ABCDEF0123456789ABCDEF",
        "spanId": "0123456789ABCDEF",
    }
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": _attributes(
                        **{
                            "service.name": "example-idp",
                            "service.version": "1.2.3",
                            "deployment.environment.name": "test",
                        }
                    )
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "example.security", "version": "1.0"},
                        "logRecords": [log_record],
                    }
                ],
            }
        ]
    }


def test_otlp_json_adapter_maps_log_record_without_timestamp_loss() -> None:
    original = json.dumps(_request(), separators=(",", ":")).encode()
    result = OTLPJSONLogAdapter().normalize(original)

    assert result.request_sha256 == hashlib.sha256(original).hexdigest()
    assert result.request_byte_count == len(original)
    assert result.accepted_log_records == 1
    assert result.rejected_log_records == 0
    event = result.events[0]
    assert event.time_unix_nano == 1_787_140_800_000_000_123
    assert event.observed_time_unix_nano == 1_787_140_801_000_000_456
    assert event.trace_id == "0123456789abcdef0123456789abcdef"
    assert event.span_id == "0123456789abcdef"
    assert event.resource.service_name == "example-idp"
    assert event.instrumentation_scope == "example.security"
    assert event.body == {"action": "login", "outcome": "failure"}
    assert event.original_event.source_type == "otlp"
    assert event.original_event.source_event_id == "source-42"


def test_otlp_json_adapter_reports_mapping_loss_and_partial_rejection() -> None:
    missing_fields = {
        "observedTimeUnixNano": "1787140801000000000",
        "severityNumber": 9,
        "body": {"stringValue": "message"},
        "attributes": [
            {"key": "nested", "value": {"arrayValue": {"values": [_any("value")]}}}
        ],
        "futureField": "ignored",
    }
    sensitive = {
        "timeUnixNano": "1787140800000000000",
        "observedTimeUnixNano": "1787140801000000000",
        "severityNumber": 9,
        "eventName": "identity.authentication.succeeded",
        "body": {"kvlistValue": {"values": _attributes(password="must-not-echo")}},
    }
    request = _request(missing_fields)
    request["resourceLogs"][0]["scopeLogs"][0]["logRecords"].append(sensitive)

    result = OTLPJSONLogAdapter().normalize(json.dumps(request).encode())

    assert result.accepted_log_records == 1
    assert result.rejected_log_records == 1
    warnings = " ".join(result.warnings)
    assert "futureField" in warnings
    assert "missing eventName mapped to otel.log" in warnings
    assert "dropped non-scalar attribute nested" in warnings
    assert "rejected" in warnings
    assert "must-not-echo" not in warnings


def test_otlp_json_adapter_ignores_unknown_fields_and_reports_empty_unknown_shape() -> None:
    request = _request()
    request["futureTopLevel"] = {"safe": True}
    accepted = OTLPJSONLogAdapter().normalize(json.dumps(request).encode())
    assert accepted.accepted_log_records == 1
    assert "futureTopLevel" in " ".join(accepted.warnings)

    unknown_shape = OTLPJSONLogAdapter().normalize(json.dumps({"resource_logs": []}).encode())
    assert unknown_shape.accepted_log_records == 0
    assert "resource_logs" in " ".join(unknown_shape.warnings)


def test_otlp_json_adapter_rejects_duplicate_attributes_and_oversized_batches() -> None:
    duplicate = _request()
    record = duplicate["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    record["attributes"] = [
        {"key": "same", "value": _any("one")},
        {"key": "same", "value": _any("two")},
    ]
    result = OTLPJSONLogAdapter().normalize(json.dumps(duplicate).encode())
    assert result.accepted_log_records == 0
    assert result.rejected_log_records == 1

    oversized = _request()
    logs = oversized["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    logs.extend([logs[0]] * 100)
    with pytest.raises(OTLPMappingError, match="100 log-record limit"):
        OTLPJSONLogAdapter().normalize(json.dumps(oversized).encode())


def test_otlp_json_adapter_bounds_untrusted_warning_text() -> None:
    request = _request()
    request["unknown\nfield" + ("x" * 1_000)] = True

    result = OTLPJSONLogAdapter().normalize(json.dumps(request).encode())

    assert len(result.warnings[0]) <= 500
    assert "\n" not in result.warnings[0]


def test_otlp_json_endpoint_is_authenticated_bounded_and_non_persistent(
    client: TestClient,
) -> None:
    original = json.dumps(_request()).encode()
    response = client.post(
        "/v1/telemetry/events/otlp-json",
        content=original,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["accepted_log_records"] == 1
    assert response.json()["request_sha256"] == hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize(
    ("content", "media_type", "expected"),
    [
        (b"not-json", "application/json", 422),
        (b"{}", "application/x-protobuf", 415),
        (b"x" * 1_048_577, "application/json", 413),
    ],
    ids=["malformed", "binary-protobuf-unsupported", "oversized"],
)
def test_otlp_json_endpoint_rejects_unsupported_or_invalid_requests(
    client: TestClient, content: bytes, media_type: str, expected: int
) -> None:
    response = client.post(
        "/v1/telemetry/events/otlp-json",
        content=content,
        headers={"Content-Type": media_type},
    )
    assert response.status_code == expected
