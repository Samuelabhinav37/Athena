import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

SECURITY_EVENT_SCHEMA = "https://athena.example/schemas/security-event/1.0"
MAX_ORIGINAL_EVENT_BYTES = 1_048_576
MAX_NORMALIZED_EVENT_BYTES = 65_536
MAX_ATTRIBUTES = 64
HEX_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
HEX_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EVENT_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


def _unix_nano(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = value - epoch
    return (
        delta.days * 86_400_000_000_000
        + delta.seconds * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                return True
            if _contains_sensitive_key(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


class OriginalEventProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_type: Literal["athena", "json", "otlp", "syslog", "webhook"]
    source_name: str = Field(min_length=1, max_length=128)
    source_event_id: str | None = Field(default=None, min_length=1, max_length=255)
    source_locator: str = Field(min_length=1, max_length=2048)
    source_format: str = Field(min_length=1, max_length=128)
    content_sha256: str
    byte_count: int = Field(ge=1, le=MAX_ORIGINAL_EVENT_BYTES)
    received_at: datetime

    @field_validator("content_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if SHA256.fullmatch(value) is None:
            raise ValueError("content_sha256 must be a lowercase SHA-256 digest")
        return value

    @field_validator("received_at")
    @classmethod
    def normalize_received_at(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("source_locator")
    @classmethod
    def reject_sensitive_locator_components(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("source_locator must not contain credentials, a query, or a fragment")
        return value


class TelemetryResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    service_name: str = Field(min_length=1, max_length=128)
    service_version: str | None = Field(default=None, max_length=64)
    deployment_environment: str | None = Field(default=None, max_length=64)
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_ATTRIBUTES:
            raise ValueError("resource attributes exceed the limit")
        if _contains_sensitive_key(value):
            raise ValueError("resource attributes contain a forbidden sensitive key")
        return value


class SecurityEventEnvelope(BaseModel):
    """Transport-neutral security event aligned with OpenTelemetry log concepts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_url: Literal[SECURITY_EVENT_SCHEMA] = SECURITY_EVENT_SCHEMA
    schema_version: Literal["1.0"] = "1.0"
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_name: str
    time_unix_nano: int = Field(gt=0)
    observed_time_unix_nano: int = Field(gt=0)
    severity_number: int = Field(ge=1, le=24)
    severity_text: str = Field(min_length=1, max_length=24)
    body: dict[str, JsonValue]
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)
    resource: TelemetryResource
    instrumentation_scope: str = Field(default="athena.security", min_length=1, max_length=128)
    trace_id: str | None = None
    span_id: str | None = None
    original_event: OriginalEventProvenance

    @field_validator("event_name")
    @classmethod
    def validate_event_name(cls, value: str) -> str:
        if EVENT_NAME.fullmatch(value) is None:
            raise ValueError("event_name must use lowercase dotted semantic naming")
        return value

    @field_validator("trace_id")
    @classmethod
    def validate_trace_id(cls, value: str | None) -> str | None:
        if value is not None and HEX_TRACE_ID.fullmatch(value) is None:
            raise ValueError("trace_id must be 32 lowercase hexadecimal characters")
        return value

    @field_validator("span_id")
    @classmethod
    def validate_span_id(cls, value: str | None) -> str | None:
        if value is not None and HEX_SPAN_ID.fullmatch(value) is None:
            raise ValueError("span_id must be 16 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def validate_bounded_normalized_content(self) -> "SecurityEventEnvelope":
        if len(self.attributes) > MAX_ATTRIBUTES:
            raise ValueError("event attributes exceed the limit")
        normalized = {"body": self.body, "attributes": self.attributes}
        if _contains_sensitive_key(normalized):
            raise ValueError("normalized event contains a forbidden sensitive key")
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_NORMALIZED_EVENT_BYTES:
            raise ValueError("normalized event exceeds the size limit")
        if (self.trace_id is None) != (self.span_id is None):
            raise ValueError("trace_id and span_id must be supplied together")
        return self


class JSONSecurityEventInput(BaseModel):
    """Caller-supplied normalized fields; transport provenance is derived by Athena."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_name: str = Field(min_length=1, max_length=128)
    source_event_id: str | None = Field(default=None, min_length=1, max_length=255)
    event_name: str
    occurred_at: datetime
    severity_number: int = Field(ge=1, le=24)
    severity_text: str = Field(min_length=1, max_length=24)
    body: dict[str, JsonValue]
    attributes: dict[str, str | int | float | bool] = Field(default_factory=dict)
    resource: TelemetryResource
    trace_id: str | None = None
    span_id: str | None = None


class OTLPNormalizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_sha256: str
    request_byte_count: int
    accepted_log_records: int
    rejected_log_records: int
    warnings: list[str]
    events: list[SecurityEventEnvelope]


class SyslogNormalizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_sha256: str
    request_byte_count: int
    framing: Literal["octet-counted", "unframed"]
    warnings: list[str]
    event: SecurityEventEnvelope


def build_security_event(
    *,
    original_bytes: bytes,
    source_type: Literal["athena", "json", "otlp", "syslog", "webhook"],
    source_name: str,
    source_locator: str,
    source_format: str,
    event_name: str,
    occurred_at: datetime,
    severity_number: int,
    severity_text: str,
    body: dict[str, JsonValue],
    resource: TelemetryResource,
    source_event_id: str | None = None,
    attributes: dict[str, str | int | float | bool] | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    received_at: datetime | None = None,
) -> SecurityEventEnvelope:
    if not original_bytes:
        raise ValueError("original event must not be empty")
    if len(original_bytes) > MAX_ORIGINAL_EVENT_BYTES:
        raise ValueError("original event exceeds the size limit")
    occurred = _utc(occurred_at)
    received = _utc(received_at or datetime.now(UTC))
    return SecurityEventEnvelope(
        event_name=event_name,
        time_unix_nano=_unix_nano(occurred),
        observed_time_unix_nano=_unix_nano(received),
        severity_number=severity_number,
        severity_text=severity_text.upper(),
        body=body,
        attributes=attributes or {},
        resource=resource,
        trace_id=trace_id,
        span_id=span_id,
        original_event=OriginalEventProvenance(
            source_type=source_type,
            source_name=source_name,
            source_event_id=source_event_id,
            source_locator=source_locator,
            source_format=source_format,
            content_sha256=hashlib.sha256(original_bytes).hexdigest(),
            byte_count=len(original_bytes),
            received_at=received,
        ),
    )
