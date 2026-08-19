import hashlib
import hmac
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError

from athena.config import Settings
from athena.telemetry import (
    WebhookEventInput,
    WebhookNormalizationResponse,
    build_security_event,
)

DELIVERY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SIGNATURE = re.compile(r"^sha256=([0-9a-f]{64})$")
TIMESTAMP = re.compile(r"^[1-9]\d{9,10}$")
MAX_REPLAY_ENTRIES = 10_000
GENERIC_CAPABILITIES = (
    "structured_body",
    "scalar_attributes",
    "resource_identity",
    "trace_context",
    "original_request_digest",
)


class WebhookAuthenticationError(ValueError):
    pass


class WebhookReplayError(ValueError):
    pass


class WebhookReplayCache:
    def __init__(
        self,
        max_entries: int = MAX_REPLAY_ENTRIES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_entries = max_entries
        self.clock = clock
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_mark(self, delivery_id: str, expires_at: float) -> None:
        now = self.clock()
        with self._lock:
            expired = [key for key, expiry in self._entries.items() if expiry <= now]
            for key in expired:
                del self._entries[key]
            if delivery_id in self._entries:
                raise WebhookReplayError("Webhook delivery was already processed")
            if len(self._entries) >= self.max_entries:
                self._entries.popitem(last=False)
            self._entries[delivery_id] = expires_at


class SignedWebhookAdapter:
    def __init__(
        self,
        settings: Settings,
        replay_cache: WebhookReplayCache,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.replay_cache = replay_cache
        self.clock = clock

    def normalize(
        self,
        *,
        original_bytes: bytes,
        timestamp_header: str,
        delivery_id: str,
        signature_header: str,
    ) -> WebhookNormalizationResponse:
        if not self.settings.webhook_enabled:
            raise WebhookAuthenticationError("Webhook receiver is disabled")
        if DELIVERY_ID.fullmatch(delivery_id) is None:
            raise WebhookAuthenticationError("Webhook delivery ID is invalid")
        if TIMESTAMP.fullmatch(timestamp_header) is None:
            raise WebhookAuthenticationError("Webhook timestamp is invalid")
        timestamp = int(timestamp_header)
        now = self.clock()
        max_age = self.settings.webhook_max_age_seconds
        if timestamp < now - max_age or timestamp > now + max_age:
            raise WebhookAuthenticationError("Webhook timestamp is outside the freshness window")
        signature_match = SIGNATURE.fullmatch(signature_header)
        if signature_match is None:
            raise WebhookAuthenticationError("Webhook signature format is invalid")
        signed = f"{timestamp_header}.{delivery_id}.".encode() + original_bytes
        expected = hmac.new(
            self.settings.webhook_secret.get_secret_value().encode(),
            signed,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature_match.group(1)):
            raise WebhookAuthenticationError("Webhook signature is invalid")
        self.replay_cache.check_and_mark(delivery_id, now + max_age)
        try:
            payload = WebhookEventInput.model_validate_json(original_bytes)
            event = build_security_event(
                original_bytes=original_bytes,
                source_type="webhook",
                source_name=payload.event.source_name,
                source_locator="athena://receiver/webhook/athena.generic.v1",
                source_format="application/json; mapping=athena.generic.v1",
                source_event_id=payload.event.source_event_id,
                event_name=payload.event.event_name,
                occurred_at=payload.event.occurred_at,
                received_at=datetime.now(UTC),
                severity_number=payload.event.severity_number,
                severity_text=payload.event.severity_text,
                body=payload.event.body,
                attributes=payload.event.attributes,
                resource=payload.event.resource,
                trace_id=payload.event.trace_id,
                span_id=payload.event.span_id,
            )
        except (ValidationError, ValueError) as error:
            raise ValueError("Invalid signed webhook event") from error
        return WebhookNormalizationResponse(
            request_sha256=hashlib.sha256(original_bytes).hexdigest(),
            request_byte_count=len(original_bytes),
            delivery_id=delivery_id,
            mapping=payload.mapping,
            capabilities=GENERIC_CAPABILITIES,
            event=event,
        )
