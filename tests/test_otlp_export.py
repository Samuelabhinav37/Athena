import json
import uuid
from datetime import UTC, datetime

import pytest
from athena.services.otlp_export import OTLPExportError, OTLPJSONExporter
from athena.telemetry import TelemetryResource, build_security_event


def _event(name: str, minute: int, event_id: str):
    timestamp = datetime(2026, 8, 19, 12, minute, tzinfo=UTC)
    event = build_security_event(
        original_bytes=f'{{"name":"{name}"}}'.encode(),
        source_type="json",
        source_name="test-source",
        source_locator="collector://test/security",
        source_format="application/json",
        source_event_id=f"source-{minute}",
        event_name=name,
        occurred_at=timestamp,
        received_at=timestamp,
        severity_number=9,
        severity_text="INFO",
        body={"name": name, "outcomes": ["allowed", True]},
        attributes={"sequence": minute},
        resource=TelemetryResource(
            service_name="test-service", deployment_environment="test"
        ),
        trace_id="0123456789abcdef0123456789abcdef",
        span_id="0123456789abcdef",
    )
    return event.model_copy(update={"event_id": uuid.UUID(event_id)})


def test_otlp_export_is_deterministic_and_preserves_semantics_and_provenance() -> None:
    first = _event("security.first", 0, "00000000-0000-0000-0000-000000000001")
    second = _event("security.second", 1, "00000000-0000-0000-0000-000000000002")
    exporter = OTLPJSONExporter()

    forward = exporter.export([first, second])
    reverse = exporter.export([second, first])
    payload = json.loads(forward.request_bytes)
    record = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    attributes = {item["key"]: item["value"] for item in record["attributes"]}

    assert forward == reverse
    assert forward.event_count == 2
    assert forward.warnings == ()
    assert record["timeUnixNano"] == str(first.time_unix_nano)
    assert record["traceId"] == first.trace_id
    assert attributes["event.name"] == {"stringValue": "security.first"}
    assert attributes["athena.original.content_sha256"] == {
        "stringValue": first.original_event.content_sha256
    }


def test_otlp_export_reports_lossy_null_and_out_of_range_integer_mapping() -> None:
    event = _event("security.first", 0, "00000000-0000-0000-0000-000000000001")
    event.body["optional"] = None
    event.body["large"] = 2**70

    exported = OTLPJSONExporter().export([event])
    body_values = json.loads(exported.request_bytes)["resourceLogs"][0]["scopeLogs"][0][
        "logRecords"
    ][0]["body"]["kvlistValue"]["values"]
    body = {item["key"]: item["value"] for item in body_values}

    assert "optional" not in body
    assert body["large"] == {"stringValue": str(2**70)}
    assert exported.warnings == (
        "body.large: integer exceeded int64 and was encoded as a string",
        "body.optional: null has no OTLP AnyValue representation and was omitted",
    )


def test_otlp_export_revalidates_events_and_rejects_duplicates_and_limit() -> None:
    event = _event("security.first", 0, "00000000-0000-0000-0000-000000000001")
    exporter = OTLPJSONExporter()

    with pytest.raises(OTLPExportError, match="duplicate event IDs"):
        exporter.export([event, event])

    event.body["access_token"] = "must-not-export"
    with pytest.raises(OTLPExportError, match="invalid security event"):
        exporter.export([event])

    clean = _event("security.first", 0, "00000000-0000-0000-0000-000000000001")
    with pytest.raises(OTLPExportError, match="1000-event limit"):
        exporter.export(
            [clean.model_copy(update={"event_id": uuid.uuid4()}) for _ in range(1001)]
        )
