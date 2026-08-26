import hashlib
import hmac
import json
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from athena.telemetry import SecurityEventEnvelope, TelemetryJSONExportPackage

EXPORT_SCHEMA_URL = "https://athena.example/schemas/telemetry-export/1.0"
MAX_EXPORT_EVENTS = 1000
MAX_EXPORT_BYTES = 8_388_608


class TelemetryExportError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _facts(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_url": EXPORT_SCHEMA_URL,
        "schema_version": "1.0",
        "export_format": "athena.telemetry+json",
        "event_count": len(events),
        "events": events,
    }


class TelemetryJSONExporter:
    def export(self, events: Iterable[SecurityEventEnvelope]) -> bytes:
        validated = []
        for event in events:
            try:
                validated.append(SecurityEventEnvelope.model_validate(event.model_dump()))
            except (AttributeError, ValidationError) as error:
                raise TelemetryExportError("Export contains an invalid security event") from error
            if len(validated) > MAX_EXPORT_EVENTS:
                raise TelemetryExportError("Export exceeds the 1000-event limit")
        ids = [str(event.event_id) for event in validated]
        if len(ids) != len(set(ids)):
            raise TelemetryExportError("Export contains duplicate event IDs")
        ordered = sorted(validated, key=lambda item: (item.time_unix_nano, str(item.event_id)))
        event_values = [event.model_dump(mode="json") for event in ordered]
        facts = _facts(event_values)
        package = {
            **facts,
            "content_sha256": hashlib.sha256(_canonical(facts)).hexdigest(),
        }
        result = _canonical(package) + b"\n"
        if len(result) > MAX_EXPORT_BYTES:
            raise TelemetryExportError("Export exceeds the 8 MiB output limit")
        return result

    def verify(self, value: bytes) -> TelemetryJSONExportPackage:
        if not value or len(value) > MAX_EXPORT_BYTES:
            raise TelemetryExportError("Export must contain between 1 byte and 8 MiB")
        try:
            package = TelemetryJSONExportPackage.model_validate_json(value)
        except ValidationError as error:
            raise TelemetryExportError("Export package is invalid") from error
        if package.event_count != len(package.events):
            raise TelemetryExportError("Export event count does not match its contents")
        ids = [str(event.event_id) for event in package.events]
        if len(ids) != len(set(ids)):
            raise TelemetryExportError("Export contains duplicate event IDs")
        event_values = [event.model_dump(mode="json") for event in package.events]
        expected = hashlib.sha256(_canonical(_facts(event_values))).hexdigest()
        if not hmac.compare_digest(expected, package.content_sha256):
            raise TelemetryExportError("Export content digest does not match")
        canonical = _canonical(package.model_dump(mode="json")) + b"\n"
        if value != canonical:
            raise TelemetryExportError("Export package is not canonically serialized")
        return package
