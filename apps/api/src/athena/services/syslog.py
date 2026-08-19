import hashlib
import re
import time
from datetime import UTC, datetime

from athena.telemetry import (
    MAX_ORIGINAL_EVENT_BYTES,
    OriginalEventProvenance,
    SecurityEventEnvelope,
    SyslogNormalizationResponse,
    TelemetryResource,
)

_HEADER = re.compile(
    r"^<(?P<priority>0|[1-9]\d{0,2})>(?P<version>[1-9]\d{0,2}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<app_name>\S+) "
    r"(?P<proc_id>\S+) (?P<msg_id>\S+) (?P<remainder>.*)$",
    re.DOTALL,
)
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_PRINT_ASCII = re.compile(r"^[!-~]+$")
_SEMANTIC_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SEVERITY = {0: 24, 1: 23, 2: 21, 3: 17, 4: 13, 5: 10, 6: 9, 7: 5}
_SEVERITY_TEXT = (
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
)


class SyslogMappingError(ValueError):
    pass


def _clean_warning(message: str) -> str:
    return " ".join(message.split())[:500]


def _unix_nano(value: datetime) -> int:
    utc_value = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    return (
        delta.days * 86_400_000_000_000
        + delta.seconds * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _nil(value: str) -> str | None:
    return None if value == "-" else value


def _field(value: str, name: str, maximum: int) -> str | None:
    normalized = _nil(value)
    if normalized is None:
        return None
    if len(normalized) > maximum or _PRINT_ASCII.fullmatch(normalized) is None:
        raise SyslogMappingError(f"{name} is invalid")
    return normalized


def _structured_data(value: str) -> tuple[dict[str, dict[str, str]], str]:
    if value.startswith("-"):
        if len(value) == 1:
            return {}, ""
        if value[1] != " ":
            raise SyslogMappingError("NIL structured data must be followed by a space")
        return {}, value[2:]
    if not value.startswith("["):
        raise SyslogMappingError("structured data is required")
    elements: dict[str, dict[str, str]] = {}
    position = 0
    while position < len(value) and value[position] == "[":
        end_id = position + 1
        while end_id < len(value) and value[end_id] not in {" ", "]"}:
            end_id += 1
        sd_id = value[position + 1 : end_id]
        if not sd_id or len(sd_id) > 32 or any(char in sd_id for char in {'=', '"', ']'}):
            raise SyslogMappingError("structured-data ID is invalid")
        if sd_id in elements:
            raise SyslogMappingError("duplicate structured-data ID")
        params: dict[str, str] = {}
        position = end_id
        while position < len(value) and value[position] != "]":
            if value[position] != " ":
                raise SyslogMappingError("structured-data parameter separator is invalid")
            position += 1
            equals = value.find("=", position)
            if equals < 0:
                raise SyslogMappingError("structured-data parameter is incomplete")
            name = value[position:equals]
            if not name or len(name) > 32 or any(char in name for char in {' ', '=', '"', ']'}):
                raise SyslogMappingError("structured-data parameter name is invalid")
            if name in params or equals + 1 >= len(value) or value[equals + 1] != '"':
                raise SyslogMappingError("structured-data parameter is invalid")
            position = equals + 2
            decoded = []
            while position < len(value):
                char = value[position]
                if char == '"':
                    position += 1
                    break
                if char == "\\":
                    position += 1
                    if position >= len(value) or value[position] not in {'"', "\\", "]"}:
                        raise SyslogMappingError("structured-data escape is invalid")
                    char = value[position]
                decoded.append(char)
                position += 1
            else:
                raise SyslogMappingError("structured-data parameter is unterminated")
            params[name] = "".join(decoded)
        if position >= len(value) or value[position] != "]":
            raise SyslogMappingError("structured-data element is unterminated")
        elements[sd_id] = params
        position += 1
    if position == len(value):
        return elements, ""
    if value[position] != " ":
        raise SyslogMappingError("structured data must be followed by a space")
    return elements, value[position + 1 :]


class SyslogAdapter:
    def normalize(self, request_bytes: bytes) -> SyslogNormalizationResponse:
        if not request_bytes or len(request_bytes) > MAX_ORIGINAL_EVENT_BYTES:
            raise SyslogMappingError("syslog request must contain between 1 byte and 1 MiB")
        message_bytes, framing = self._frame(request_bytes)
        try:
            message = message_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SyslogMappingError("syslog message must be UTF-8") from error
        match = _HEADER.fullmatch(message)
        if match is None:
            raise SyslogMappingError("message is not RFC 5424 syslog")
        values = match.groupdict()
        priority = int(values["priority"])
        if priority > 191 or values["version"] != "1":
            raise SyslogMappingError("unsupported syslog priority or version")
        hostname = _field(values["hostname"], "HOSTNAME", 255)
        app_name = _field(values["app_name"], "APP-NAME", 48)
        proc_id = _field(values["proc_id"], "PROCID", 128)
        msg_id = _field(values["msg_id"], "MSGID", 32)
        structured, text = _structured_data(values["remainder"])
        warnings = []
        received = datetime.now(UTC)
        observed_nano = time.time_ns()
        if values["timestamp"] == "-":
            occurred_nano = observed_nano
            warnings.append("missing TIMESTAMP replaced at receipt")
        else:
            if _TIMESTAMP.fullmatch(values["timestamp"]) is None:
                raise SyslogMappingError("TIMESTAMP is not valid RFC 5424 format")
            try:
                timestamp = datetime.fromisoformat(values["timestamp"].replace("Z", "+00:00"))
            except ValueError as error:
                raise SyslogMappingError("TIMESTAMP is invalid") from error
            occurred_nano = _unix_nano(timestamp)
        event_name = (
            msg_id.lower()
            if msg_id and _SEMANTIC_NAME.fullmatch(msg_id.lower())
            else "syslog.message"
        )
        if event_name == "syslog.message" and msg_id:
            warnings.append("MSGID could not be used as a semantic event name")
        body = {
            "message": text.removeprefix("\ufeff"),
            "structured_data": structured,
            "hostname": hostname,
            "app_name": app_name,
            "proc_id": proc_id,
            "msg_id": msg_id,
            "facility": priority // 8,
            "syslog_severity": priority % 8,
        }
        event = SecurityEventEnvelope(
            event_name=event_name,
            time_unix_nano=occurred_nano,
            observed_time_unix_nano=observed_nano,
            severity_number=_SEVERITY[priority % 8],
            severity_text=_SEVERITY_TEXT[priority % 8],
            body=body,
            attributes={"syslog.facility": priority // 8, "syslog.priority": priority},
            resource=TelemetryResource(service_name=app_name or "syslog-unknown-application"),
            instrumentation_scope="athena.syslog.rfc5424",
            original_event=OriginalEventProvenance(
                source_type="syslog",
                source_name=hostname or app_name or "syslog-unknown-source",
                source_event_id=msg_id,
                source_locator="athena://receiver/syslog",
                source_format=f"application/syslog; framing={framing}",
                content_sha256=hashlib.sha256(message_bytes).hexdigest(),
                byte_count=len(message_bytes),
                received_at=received,
            ),
        )
        return SyslogNormalizationResponse(
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            request_byte_count=len(request_bytes),
            framing=framing,
            warnings=[_clean_warning(item) for item in warnings],
            event=event,
        )

    @staticmethod
    def _frame(value: bytes) -> tuple[bytes, str]:
        if value[:1].isdigit():
            separator = value.find(b" ")
            if separator <= 0:
                raise SyslogMappingError("octet-counted frame is incomplete")
            length_text = value[:separator]
            if length_text.startswith(b"0") or not length_text.isdigit():
                raise SyslogMappingError("octet count is invalid")
            length = int(length_text)
            message = value[separator + 1 :]
            if length != len(message):
                raise SyslogMappingError("octet count does not match message bytes")
            return message, "octet-counted"
        if b"\n" in value or b"\r" in value or b"\x00" in value:
            raise SyslogMappingError("delimiter-framed syslog is not supported")
        return value, "unframed"
