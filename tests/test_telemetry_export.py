import json
import uuid
from datetime import UTC, datetime

import pytest
from athena.services.telemetry_export import TelemetryExportError, TelemetryJSONExporter
from athena.telemetry import TelemetryResource, build_security_event


def _event(name: str, timestamp: datetime, event_id: uuid.UUID):
    event = build_security_event(
        original_bytes=f'{{"name":"{name}"}}'.encode(),
        source_type="json",
        source_name="test-source",
        source_locator="collector://test/security",
        source_format="application/json",
        event_name=name,
        occurred_at=timestamp,
        received_at=timestamp,
        severity_number=9,
        severity_text="INFO",
        body={"name": name},
        resource=TelemetryResource(service_name="test-service"),
    )
    return event.model_copy(update={"event_id": event_id})


def test_json_export_is_deterministic_sorted_and_preserves_provenance() -> None:
    first = _event(
        "security.first",
        datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    second = _event(
        "security.second",
        datetime(2026, 8, 19, 12, 1, tzinfo=UTC),
        uuid.UUID("00000000-0000-0000-0000-000000000002"),
    )
    exporter = TelemetryJSONExporter()

    forward = exporter.export([first, second])
    reverse = exporter.export([second, first])
    package = exporter.verify(forward)

    assert forward == reverse
    assert forward.endswith(b"\n")
    assert package.event_count == 2
    assert [event.event_name for event in package.events] == ["security.first", "security.second"]
    assert package.events[0].original_event.content_sha256 == first.original_event.content_sha256


def test_json_export_digest_changes_with_authoritative_event_content() -> None:
    event_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    timestamp = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
    first = _event("security.first", timestamp, event_id)
    changed = _event("security.changed", timestamp, event_id)
    exporter = TelemetryJSONExporter()

    first_package = exporter.verify(exporter.export([first]))
    changed_package = exporter.verify(exporter.export([changed]))

    assert first_package.content_sha256 != changed_package.content_sha256


def test_json_export_revalidates_mutated_nested_content_for_secret_keys() -> None:
    event = _event(
        "security.first",
        datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    event.body["authorization"] = "Bearer must-not-export"

    with pytest.raises(TelemetryExportError, match="invalid security event"):
        TelemetryJSONExporter().export([event])


def test_json_export_rejects_duplicate_ids_and_event_limit() -> None:
    event = _event(
        "security.first",
        datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    exporter = TelemetryJSONExporter()

    with pytest.raises(TelemetryExportError, match="duplicate event IDs"):
        exporter.export([event, event])
    with pytest.raises(TelemetryExportError, match="1000-event limit"):
        exporter.export([event.model_copy(update={"event_id": uuid.uuid4()}) for _ in range(1001)])


def test_json_export_verification_rejects_tampering_and_noncanonical_json() -> None:
    event = _event(
        "security.first",
        datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        uuid.UUID("00000000-0000-0000-0000-000000000001"),
    )
    exporter = TelemetryJSONExporter()
    exported = exporter.export([event])
    tampered = json.loads(exported)
    tampered["events"][0]["body"]["name"] = "tampered"

    with pytest.raises(TelemetryExportError, match="digest does not match"):
        exporter.verify(
            json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
    with pytest.raises(TelemetryExportError, match="not canonically serialized"):
        exporter.verify(json.dumps(json.loads(exported), indent=2).encode())
