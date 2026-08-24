import json
import logging
import re
import sys
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from threading import Lock
from typing import Any

REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
logger = logging.getLogger("athena.requests")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    request_handler = logging.StreamHandler(sys.stdout)
    request_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(request_handler)


class MetricsRegistry:
    def __init__(self) -> None:
        self._requests: Counter[tuple[str, str]] = Counter()
        self._duration_seconds = 0.0
        self._lock = Lock()

    def observe_request(self, method: str, status_code: int, duration_seconds: float) -> None:
        status_class = f"{status_code // 100}xx"
        with self._lock:
            self._requests[(method, status_class)] += 1
            self._duration_seconds += duration_seconds

    def render(self) -> str:
        with self._lock:
            requests = tuple(sorted(self._requests.items()))
            duration = self._duration_seconds
        lines = [
            "# HELP athena_http_requests_total HTTP requests by method and status class.",
            "# TYPE athena_http_requests_total counter",
        ]
        lines.extend(
            f'athena_http_requests_total{{method="{method}",status_class="{status}"}} {count}'
            for (method, status), count in requests
        )
        lines.extend(
            [
                "# HELP athena_http_request_duration_seconds_sum Total HTTP request duration.",
                "# TYPE athena_http_request_duration_seconds_sum counter",
                f"athena_http_request_duration_seconds_sum {duration:.6f}",
            ]
        )
        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()


class RequestObservabilityMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        supplied = headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        request_id = supplied if REQUEST_ID_PATTERN.fullmatch(supplied) else str(uuid.uuid4())
        started = time.perf_counter()
        status_code = 500

        async def send_with_context(message: dict[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers = list(message.get("headers", []))
                response_headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_context)
        finally:
            duration_seconds = time.perf_counter() - started
            metrics.observe_request(
                str(scope.get("method", "UNKNOWN")), status_code, duration_seconds
            )
            logger.info(
                json.dumps(
                    {
                        "event": "http_request",
                        "request_id": request_id,
                        "method": scope.get("method"),
                        "path": scope.get("path"),
                        "status": status_code,
                        "duration_ms": round(duration_seconds * 1000, 3),
                    },
                    separators=(",", ":"),
                )
            )
