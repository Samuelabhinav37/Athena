import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from athena.telemetry import SecurityEventEnvelope

MAX_OTLP_EXPORT_EVENTS = 1000
MAX_OTLP_EXPORT_BYTES = 8_388_608
MAX_OTLP_EXPORT_WARNINGS = 100
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1
_UNSUPPORTED = object()


class OTLPExportError(ValueError):
    pass


@dataclass(frozen=True)
class OTLPJSONExport:
    request_bytes: bytes
    event_count: int
    warnings: tuple[str, ...]
    content_sha256: str


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _warn(warnings: list[str], message: str) -> None:
    if message not in warnings and len(warnings) < MAX_OTLP_EXPORT_WARNINGS:
        warnings.append(message)


def _any_value(value: Any, path: str, warnings: list[str]) -> dict[str, Any] | object:
    if value is None:
        _warn(warnings, f"{path}: null has no OTLP AnyValue representation and was omitted")
        return _UNSUPPORTED
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, int):
        if _INT64_MIN <= value <= _INT64_MAX:
            return {"intValue": str(value)}
        _warn(warnings, f"{path}: integer exceeded int64 and was encoded as a string")
        return {"stringValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list):
        mapped = []
        for index, item in enumerate(value):
            converted = _any_value(item, f"{path}[{index}]", warnings)
            if converted is not _UNSUPPORTED:
                mapped.append(converted)
        return {"arrayValue": {"values": mapped}}
    if isinstance(value, dict):
        mapped_values = []
        for key in sorted(value):
            converted = _any_value(value[key], f"{path}.{key}", warnings)
            if converted is not _UNSUPPORTED:
                mapped_values.append({"key": key, "value": converted})
        return {"kvlistValue": {"values": mapped_values}}
    raise OTLPExportError(f"{path}: value cannot be represented as OTLP AnyValue")


def _attributes(values: dict[str, Any], path: str, warnings: list[str]) -> list[dict[str, Any]]:
    result = []
    for key in sorted(values):
        converted = _any_value(values[key], f"{path}.{key}", warnings)
        if converted is not _UNSUPPORTED:
            result.append({"key": key, "value": converted})
    return result


class OTLPJSONExporter:
    """Map canonical events to a deterministic OTLP ExportLogsServiceRequest."""

    def export(self, events: Iterable[SecurityEventEnvelope]) -> OTLPJSONExport:
        validated = []
        for event in events:
            try:
                validated.append(SecurityEventEnvelope.model_validate(event.model_dump()))
            except (AttributeError, ValidationError) as error:
                raise OTLPExportError("Export contains an invalid security event") from error
            if len(validated) > MAX_OTLP_EXPORT_EVENTS:
                raise OTLPExportError("Export exceeds the 1000-event limit")

        ids = [str(event.event_id) for event in validated]
        if len(ids) != len(set(ids)):
            raise OTLPExportError("Export contains duplicate event IDs")

        warnings: list[str] = []
        resource_logs = []
        for event in sorted(validated, key=lambda item: (item.time_unix_nano, str(item.event_id))):
            resource_values = {
                "service.name": event.resource.service_name,
                **event.resource.attributes,
            }
            if event.resource.service_version is not None:
                resource_values["service.version"] = event.resource.service_version
            if event.resource.deployment_environment is not None:
                resource_values["deployment.environment.name"] = (
                    event.resource.deployment_environment
                )

            provenance = event.original_event
            record_values = {
                **event.attributes,
                "event.name": event.event_name,
                "athena.event.id": str(event.event_id),
                "athena.original.byte_count": provenance.byte_count,
                "athena.original.content_sha256": provenance.content_sha256,
                "athena.original.received_at": provenance.received_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "athena.original.source_format": provenance.source_format,
                "athena.original.source_locator": provenance.source_locator,
                "athena.original.source_name": provenance.source_name,
                "athena.original.source_type": provenance.source_type,
            }
            if provenance.source_event_id is not None:
                record_values["athena.original.source_event_id"] = provenance.source_event_id

            record = {
                "timeUnixNano": str(event.time_unix_nano),
                "observedTimeUnixNano": str(event.observed_time_unix_nano),
                "severityNumber": event.severity_number,
                "severityText": event.severity_text,
                "body": _any_value(event.body, "body", warnings),
                "attributes": _attributes(record_values, "attributes", warnings),
            }
            if event.trace_id is not None:
                record["traceId"] = event.trace_id
                record["spanId"] = event.span_id

            resource_logs.append(
                {
                    "resource": {
                        "attributes": _attributes(resource_values, "resource.attributes", warnings)
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": event.instrumentation_scope},
                            "schemaUrl": event.schema_url,
                            "logRecords": [record],
                        }
                    ],
                }
            )

        request_bytes = _canonical({"resourceLogs": resource_logs}) + b"\n"
        if len(request_bytes) > MAX_OTLP_EXPORT_BYTES:
            raise OTLPExportError("Export exceeds the 8 MiB output limit")
        return OTLPJSONExport(
            request_bytes=request_bytes,
            event_count=len(validated),
            warnings=tuple(warnings),
            content_sha256=hashlib.sha256(request_bytes).hexdigest(),
        )
