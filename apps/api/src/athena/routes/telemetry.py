import json
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from datetime import UTC, datetime
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import ValidationError

from athena.auth import AdministratorPrincipal, require_administrator
from athena.telemetry import (
    MAX_ORIGINAL_EVENT_BYTES,
    JSONSecurityEventInput,
    SecurityEventEnvelope,
    build_security_event,
)

JSON_RATE_LIMIT = 60
JSON_RATE_WINDOW_SECONDS = 60.0
MAX_RATE_LIMIT_SUBJECTS = 10_000


class SubjectRateLimiter:
    def __init__(
        self,
        limit: int = JSON_RATE_LIMIT,
        window_seconds: float = JSON_RATE_WINDOW_SECONDS,
        max_subjects: int = MAX_RATE_LIMIT_SUBJECTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_subjects = max_subjects
        self.clock = clock
        self._requests: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, subject: str) -> int | None:
        now = self.clock()
        cutoff = now - self.window_seconds
        with self._lock:
            requests = self._requests.get(subject)
            if requests is None:
                if len(self._requests) >= self.max_subjects:
                    self._requests.popitem(last=False)
                requests = deque()
                self._requests[subject] = requests
            else:
                self._requests.move_to_end(subject)
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self.limit:
                return max(1, math.ceil(self.window_seconds - (now - requests[0])))
            requests.append(now)
        return None


@lru_cache
def get_json_rate_limiter() -> SubjectRateLimiter:
    return SubjectRateLimiter()


router = APIRouter(
    prefix="/v1/telemetry/events",
    tags=["telemetry"],
    dependencies=[Depends(require_administrator)],
)


async def _bounded_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_length = int(declared)
            if declared_length < 0:
                raise ValueError
            if declared_length > MAX_ORIGINAL_EVENT_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="JSON security event exceeds the size limit",
                )
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Content-Length header",
            ) from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_ORIGINAL_EVENT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail="JSON security event exceeds the size limit",
            )
    if not body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON security event body is required",
        )
    return bytes(body)


@router.post("/json", response_model=SecurityEventEnvelope, status_code=status.HTTP_200_OK)
async def receive_json_security_event(
    request: Request,
    response: Response,
    principal: AdministratorPrincipal,
    limiter: Annotated[SubjectRateLimiter, Depends(get_json_rate_limiter)],
) -> SecurityEventEnvelope:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Content-Type must be application/json",
        )
    retry_after = limiter.check(principal.subject)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="JSON security-event rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
    original_bytes = await _bounded_body(request)
    try:
        payload = JSONSecurityEventInput.model_validate(json.loads(original_bytes))
        envelope = build_security_event(
            original_bytes=original_bytes,
            source_type="json",
            source_name=payload.source_name,
            source_locator="athena://receiver/json",
            source_format="application/json",
            source_event_id=payload.source_event_id,
            event_name=payload.event_name,
            occurred_at=payload.occurred_at,
            received_at=datetime.now(UTC),
            severity_number=payload.severity_number,
            severity_text=payload.severity_text,
            body=payload.body,
            attributes=payload.attributes,
            resource=payload.resource,
            trace_id=payload.trace_id,
            span_id=payload.span_id,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid JSON security event",
        ) from error
    response.headers["Cache-Control"] = "no-store"
    return envelope
