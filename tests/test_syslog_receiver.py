import hashlib
from collections.abc import Generator

import pytest
from athena.config import Settings, get_settings
from athena.main import app
from athena.routes.telemetry import get_json_rate_limiter
from athena.services.syslog import SyslogAdapter, SyslogMappingError
from fastapi.testclient import TestClient

MESSAGE = (
    b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 '
    b'[exampleSDID@32473 iut="3" eventSource="Application" escaped="a\\]b"] '
    b'\xef\xbb\xbfAn application event log entry'
)


@pytest.fixture
def client() -> Generator[TestClient]:
    app.dependency_overrides[get_settings] = lambda: Settings(auth_required=False)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    get_json_rate_limiter.cache_clear()


def test_syslog_adapter_maps_rfc5424_fields_and_structured_data() -> None:
    result = SyslogAdapter().normalize(MESSAGE)

    assert result.framing == "unframed"
    assert result.request_sha256 == hashlib.sha256(MESSAGE).hexdigest()
    assert result.event.time_unix_nano == 1_065_910_455_003_000_000
    assert result.event.severity_number == 10
    assert result.event.severity_text == "NOTICE"
    assert result.event.event_name == "id47"
    assert result.event.resource.service_name == "evntslog"
    assert result.event.body["facility"] == 20
    assert result.event.body["message"] == "An application event log entry"
    assert result.event.body["structured_data"]["exampleSDID@32473"] == {
        "iut": "3",
        "eventSource": "Application",
        "escaped": "a]b",
    }
    assert result.event.original_event.content_sha256 == hashlib.sha256(MESSAGE).hexdigest()


def test_syslog_adapter_validates_exact_octet_counting() -> None:
    framed = str(len(MESSAGE)).encode() + b" " + MESSAGE
    result = SyslogAdapter().normalize(framed)

    assert result.framing == "octet-counted"
    assert result.request_sha256 == hashlib.sha256(framed).hexdigest()
    assert result.event.original_event.content_sha256 == hashlib.sha256(MESSAGE).hexdigest()

    with pytest.raises(SyslogMappingError, match="does not match"):
        SyslogAdapter().normalize(b"1 " + MESSAGE)


@pytest.mark.parametrize(
    ("message", "error"),
    [
        (b"<165>Oct 11 legacy", "not RFC 5424"),
        (MESSAGE + b"\n", "delimiter-framed"),
        (MESSAGE.replace(b"<165>1", b"<192>1"), "priority or version"),
        (MESSAGE.replace(b".003Z", b".0000003Z"), "TIMESTAMP"),
        (MESSAGE.replace(b'escaped="a\\]b"', b'escaped="a\\qb"'), "escape"),
    ],
    ids=["legacy", "delimiter", "priority", "timestamp", "escape"],
)
def test_syslog_adapter_rejects_ambiguous_or_invalid_messages(
    message: bytes, error: str
) -> None:
    with pytest.raises(SyslogMappingError, match=error):
        SyslogAdapter().normalize(message)


def test_syslog_adapter_handles_nil_fields_with_explicit_warning() -> None:
    message = b"<14>1 - - - - - - message"
    result = SyslogAdapter().normalize(message)

    assert result.event.event_name == "syslog.message"
    assert result.event.resource.service_name == "syslog-unknown-application"
    assert "missing TIMESTAMP" in " ".join(result.warnings)


def test_syslog_endpoint_normalizes_without_claiming_persistence(client: TestClient) -> None:
    response = client.post(
        "/v1/telemetry/events/syslog",
        content=MESSAGE,
        headers={"Content-Type": "application/syslog"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["event"]["original_event"]["byte_count"] == len(MESSAGE)


@pytest.mark.parametrize(
    ("content", "media_type", "expected"),
    [
        (b"not-syslog", "application/syslog", 422),
        (MESSAGE, "application/json", 415),
        (b"x" * 1_048_577, "application/syslog", 413),
    ],
    ids=["malformed", "wrong-media-type", "oversized"],
)
def test_syslog_endpoint_rejects_invalid_requests_without_echoing_content(
    client: TestClient, content: bytes, media_type: str, expected: int
) -> None:
    response = client.post(
        "/v1/telemetry/events/syslog",
        content=content,
        headers={"Content-Type": media_type},
    )
    assert response.status_code == expected
    assert "not-syslog" not in response.text
