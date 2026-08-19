import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from athena.telemetry import (
    MAX_ORIGINAL_EVENT_BYTES,
    OriginalEventProvenance,
    OTLPNormalizationResponse,
    SecurityEventEnvelope,
    TelemetryResource,
)

MAX_OTLP_LOG_RECORDS = 100
MAX_OTLP_WARNINGS = 100
_ANY_VALUE_FIELDS = {
    "arrayValue",
    "boolValue",
    "bytesValue",
    "doubleValue",
    "intValue",
    "kvlistValue",
    "stringValue",
}


class OTLPMappingError(ValueError):
    pass


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _warning(warnings: list[str], message: str) -> None:
    bounded = " ".join(message.split())[:500]
    if bounded not in warnings and len(warnings) < MAX_OTLP_WARNINGS:
        warnings.append(bounded)


def _unknown_fields(
    value: dict[str, Any], supported: set[str], path: str, warnings: list[str]
) -> None:
    unknown = sorted(set(value) - supported)
    if unknown:
        _warning(warnings, f"{path}: ignored unknown fields {', '.join(unknown)}")


def _any_value(value: Any, path: str, warnings: list[str]) -> Any:
    if not isinstance(value, dict):
        raise OTLPMappingError(f"{path}: AnyValue must be an object")
    fields = [field for field in _ANY_VALUE_FIELDS if field in value]
    if len(fields) != 1:
        raise OTLPMappingError(f"{path}: AnyValue must contain exactly one supported value")
    field = fields[0]
    _unknown_fields(value, _ANY_VALUE_FIELDS, path, warnings)
    raw = value[field]
    if field == "stringValue":
        if not isinstance(raw, str):
            raise OTLPMappingError(f"{path}: stringValue must be a string")
        return raw
    if field == "boolValue":
        if not isinstance(raw, bool):
            raise OTLPMappingError(f"{path}: boolValue must be a boolean")
        return raw
    if field == "intValue":
        if isinstance(raw, bool) or not isinstance(raw, (int, str)):
            raise OTLPMappingError(f"{path}: intValue must be an integer or decimal string")
        try:
            return int(raw)
        except ValueError as error:
            raise OTLPMappingError(f"{path}: intValue must be a decimal integer") from error
    if field == "doubleValue":
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise OTLPMappingError(f"{path}: doubleValue must be numeric")
        return float(raw)
    if field == "bytesValue":
        if not isinstance(raw, str):
            raise OTLPMappingError(f"{path}: bytesValue must be a base64 string")
        _warning(warnings, f"{path}: bytesValue retained as encoded text")
        return raw
    if field == "arrayValue":
        if not isinstance(raw, dict) or not isinstance(raw.get("values", []), list):
            raise OTLPMappingError(f"{path}: arrayValue.values must be an array")
        _unknown_fields(raw, {"values"}, f"{path}.arrayValue", warnings)
        return [
            _any_value(item, f"{path}.arrayValue.values[{index}]", warnings)
            for index, item in enumerate(raw.get("values", []))
        ]
    if not isinstance(raw, dict) or not isinstance(raw.get("values", []), list):
        raise OTLPMappingError(f"{path}: kvlistValue.values must be an array")
    _unknown_fields(raw, {"values"}, f"{path}.kvlistValue", warnings)
    return _key_values(raw.get("values", []), f"{path}.kvlistValue.values", warnings)


def _key_values(values: Any, path: str, warnings: list[str]) -> dict[str, Any]:
    if not isinstance(values, list):
        raise OTLPMappingError(f"{path} must be an array")
    result: dict[str, Any] = {}
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            raise OTLPMappingError(f"{path}[{index}] must be an object")
        _unknown_fields(item, {"key", "value"}, f"{path}[{index}]", warnings)
        key = item.get("key")
        if not isinstance(key, str) or not key:
            raise OTLPMappingError(f"{path}[{index}].key must be a non-empty string")
        if key in result:
            raise OTLPMappingError(f"{path} contains duplicate key {key}")
        result[key] = _any_value(item.get("value"), f"{path}[{index}].value", warnings)
    return result


def _scalar_attributes(values: Any, path: str, warnings: list[str]) -> dict[str, Any]:
    decoded = _key_values(values, path, warnings)
    result = {}
    for key, value in decoded.items():
        if isinstance(value, (str, int, float, bool)):
            result[key] = value
        else:
            _warning(warnings, f"{path}: dropped non-scalar attribute {key}")
    return result


def _nano(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise OTLPMappingError(f"{path} must be an integer or decimal string")
    try:
        result = int(value)
    except ValueError as error:
        raise OTLPMappingError(f"{path} must be a decimal integer") from error
    if result <= 0:
        raise OTLPMappingError(f"{path} must be greater than zero")
    return result


class OTLPJSONLogAdapter:
    def normalize(self, original_bytes: bytes) -> OTLPNormalizationResponse:
        if not original_bytes or len(original_bytes) > MAX_ORIGINAL_EVENT_BYTES:
            raise OTLPMappingError("OTLP request must contain between 1 byte and 1 MiB")
        try:
            request = json.loads(original_bytes)
        except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as error:
            raise OTLPMappingError("OTLP request must be valid JSON") from error
        if not isinstance(request, dict):
            raise OTLPMappingError("OTLP request must be an object")
        warnings: list[str] = []
        _unknown_fields(request, {"resourceLogs"}, "request", warnings)
        resource_logs = request.get("resourceLogs", [])
        if not isinstance(resource_logs, list):
            raise OTLPMappingError("resourceLogs must be an array")
        records: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]] = []
        for resource_index, resource_item in enumerate(resource_logs):
            if not isinstance(resource_item, dict):
                raise OTLPMappingError(f"resourceLogs[{resource_index}] must be an object")
            _unknown_fields(
                resource_item,
                {"resource", "scopeLogs", "schemaUrl"},
                f"resourceLogs[{resource_index}]",
                warnings,
            )
            resource = resource_item.get("resource", {})
            scopes = resource_item.get("scopeLogs", [])
            if not isinstance(resource, dict) or not isinstance(scopes, list):
                raise OTLPMappingError(f"resourceLogs[{resource_index}] has invalid structure")
            for scope_index, scope_item in enumerate(scopes):
                if not isinstance(scope_item, dict):
                    raise OTLPMappingError(
                        f"resourceLogs[{resource_index}].scopeLogs[{scope_index}] must be an object"
                    )
                _unknown_fields(
                    scope_item,
                    {"scope", "logRecords", "schemaUrl"},
                    f"resourceLogs[{resource_index}].scopeLogs[{scope_index}]",
                    warnings,
                )
                scope = scope_item.get("scope", {})
                logs = scope_item.get("logRecords", [])
                if not isinstance(scope, dict) or not isinstance(logs, list):
                    raise OTLPMappingError("scopeLogs entry has invalid structure")
                for record_index, record in enumerate(logs):
                    if not isinstance(record, dict):
                        raise OTLPMappingError("logRecords entry must be an object")
                    path = (
                        f"resourceLogs[{resource_index}].scopeLogs[{scope_index}]"
                        f".logRecords[{record_index}]"
                    )
                    records.append((resource, scope, record, path))
                    if len(records) > MAX_OTLP_LOG_RECORDS:
                        raise OTLPMappingError("OTLP request exceeds the 100 log-record limit")

        events = []
        rejected = 0
        received = datetime.now(UTC)
        observed_fallback = time.time_ns()
        for resource, scope, record, path in records:
            try:
                events.append(
                    self._record(
                        resource,
                        scope,
                        record,
                        path,
                        warnings,
                        received,
                        observed_fallback,
                    )
                )
            except OTLPMappingError as error:
                rejected += 1
                _warning(warnings, f"{path}: rejected ({error})")
            except (RecursionError, ValidationError, ValueError):
                rejected += 1
                _warning(warnings, f"{path}: rejected by Athena envelope validation")
        return OTLPNormalizationResponse(
            request_sha256=hashlib.sha256(original_bytes).hexdigest(),
            request_byte_count=len(original_bytes),
            accepted_log_records=len(events),
            rejected_log_records=rejected,
            warnings=warnings,
            events=events,
        )

    def _record(
        self,
        resource: dict[str, Any],
        scope: dict[str, Any],
        record: dict[str, Any],
        path: str,
        warnings: list[str],
        received: datetime,
        observed_fallback: int,
    ) -> SecurityEventEnvelope:
        _unknown_fields(
            resource,
            {"attributes", "droppedAttributesCount", "entityRefs"},
            f"{path}.resource",
            warnings,
        )
        _unknown_fields(
            scope,
            {"name", "version", "attributes", "droppedAttributesCount"},
            f"{path}.scope",
            warnings,
        )
        _unknown_fields(
            record,
            {
                "attributes", "body", "droppedAttributesCount", "eventName", "flags",
                "observedTimeUnixNano", "severityNumber", "severityText", "spanId",
                "timeUnixNano", "traceId",
            },
            path,
            warnings,
        )
        resource_attributes = _scalar_attributes(
            resource.get("attributes", []), f"{path}.resource.attributes", warnings
        )
        service_name = resource_attributes.pop("service.name", "otlp-unknown-service")
        if not isinstance(service_name, str) or not service_name:
            raise OTLPMappingError("resource service.name must be a non-empty string")
        attributes = _scalar_attributes(
            record.get("attributes", []), f"{path}.attributes", warnings
        )
        body_value = _any_value(record.get("body", {"stringValue": ""}), f"{path}.body", warnings)
        body = body_value if isinstance(body_value, dict) else {"value": body_value}
        event_name = record.get("eventName") or "otel.log"
        if "eventName" not in record:
            _warning(warnings, f"{path}: missing eventName mapped to otel.log")
        severity_number = record.get("severityNumber")
        if not isinstance(severity_number, int) or isinstance(severity_number, bool):
            raise OTLPMappingError("severityNumber must be an integer enum value")
        severity_text = record.get("severityText") or f"OTEL-{severity_number}"
        if not isinstance(severity_text, str):
            raise OTLPMappingError("severityText must be a string")
        observed = record.get("observedTimeUnixNano")
        observed_nano = (
            _nano(observed, "observedTimeUnixNano")
            if observed not in (None, "0", 0)
            else observed_fallback
        )
        if observed in (None, "0", 0):
            _warning(warnings, f"{path}: missing observedTimeUnixNano replaced at receipt")
        occurred = record.get("timeUnixNano")
        time_nano = (
            _nano(occurred, "timeUnixNano")
            if occurred not in (None, "0", 0)
            else observed_nano
        )
        if occurred in (None, "0", 0):
            _warning(warnings, f"{path}: missing timeUnixNano replaced by observed time")
        trace_id = record.get("traceId") or None
        span_id = record.get("spanId") or None
        serialized_record = _canonical_bytes(
            {"resource": resource, "scope": scope, "logRecord": record}
        )
        source_event_id = attributes.get("event.id")
        return SecurityEventEnvelope(
            event_name=event_name,
            time_unix_nano=time_nano,
            observed_time_unix_nano=observed_nano,
            severity_number=severity_number,
            severity_text=severity_text,
            body=body,
            attributes=attributes,
            resource=TelemetryResource(
                service_name=service_name,
                service_version=resource_attributes.pop("service.version", None),
                deployment_environment=resource_attributes.pop("deployment.environment.name", None),
                attributes=resource_attributes,
            ),
            instrumentation_scope=scope.get("name") or "unknown",
            trace_id=trace_id.lower() if isinstance(trace_id, str) else trace_id,
            span_id=span_id.lower() if isinstance(span_id, str) else span_id,
            original_event=OriginalEventProvenance(
                source_type="otlp",
                source_name=service_name,
                source_event_id=str(source_event_id) if source_event_id is not None else None,
                source_locator="athena://receiver/otlp-json",
                source_format="application/otlp+json; canonical-record=1",
                content_sha256=hashlib.sha256(serialized_record).hexdigest(),
                byte_count=len(serialized_record),
                received_at=received,
            ),
        )
