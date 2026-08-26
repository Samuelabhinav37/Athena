import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from athena.models import RateLimitBucket, RequestReplay
from athena.tenant_queries import tenant_select


class RequestControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReplayAdmission:
    replayed: bool
    reservation_id: object


@dataclass(frozen=True)
class RateLimitAdmission:
    allowed: bool
    remaining: int
    retry_after_seconds: int | None


class RequestControls:
    """Provide database-coordinated replay and fixed-window admission controls."""

    def __init__(
        self,
        session: Session,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.session = session
        self.clock = clock

    def reserve(
        self,
        *,
        namespace: str,
        idempotency_key: str,
        request_bytes: bytes,
        ttl: timedelta,
    ) -> ReplayAdmission:
        namespace = self._required(namespace, "Namespace")
        key = self._required(idempotency_key, "Idempotency key")
        digest = hashlib.sha256(request_bytes).hexdigest()
        existing = self._replay(namespace, key)
        if existing is not None:
            if existing.request_sha256 != digest:
                raise RequestControlError("Idempotency key was reused with a different request")
            return ReplayAdmission(True, existing.id)
        reservation = RequestReplay(
            tenant_id=self._tenant_id(),
            namespace=namespace,
            idempotency_key=key,
            request_sha256=digest,
            expires_at=self.clock() + ttl,
        )
        try:
            with self.session.begin_nested():
                self.session.add(reservation)
                self.session.flush()
        except IntegrityError:
            existing = self._replay(namespace, key)
            if existing is None or existing.request_sha256 != digest:
                raise RequestControlError("Concurrent idempotency request conflicted") from None
            return ReplayAdmission(True, existing.id)
        return ReplayAdmission(False, reservation.id)

    def admit(
        self,
        *,
        namespace: str,
        subject: str,
        limit: int,
        window: timedelta,
    ) -> RateLimitAdmission:
        if limit < 1 or window.total_seconds() < 1:
            raise RequestControlError("Rate limit and window must be positive")
        namespace = self._required(namespace, "Namespace")
        subject = self._required(subject, "Subject")
        now = self.clock()
        seconds = int(window.total_seconds())
        window_start = datetime.fromtimestamp(int(now.timestamp()) // seconds * seconds, tz=UTC)
        statement = tenant_select(
            self.session,
            RateLimitBucket,
            RateLimitBucket.namespace == namespace,
            RateLimitBucket.subject == subject,
            RateLimitBucket.window_started_at == window_start,
        ).with_for_update()
        bucket = self.session.scalar(statement)
        if bucket is None:
            bucket = RateLimitBucket(
                tenant_id=self._tenant_id(),
                namespace=namespace,
                subject=subject,
                window_started_at=window_start,
                request_count=1,
                expires_at=window_start + window,
            )
            try:
                with self.session.begin_nested():
                    self.session.add(bucket)
                    self.session.flush()
                return RateLimitAdmission(True, limit - 1, None)
            except IntegrityError:
                bucket = self.session.scalar(statement)
                if bucket is None:
                    raise RequestControlError("Concurrent rate-limit admission failed") from None
        if bucket.request_count >= limit:
            expires_at = bucket.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            retry_after = max(1, int((expires_at - now).total_seconds()))
            return RateLimitAdmission(False, 0, retry_after)
        bucket.request_count += 1
        self.session.flush()
        return RateLimitAdmission(True, limit - bucket.request_count, None)

    def _replay(self, namespace: str, key: str) -> RequestReplay | None:
        return self.session.scalar(
            tenant_select(
                self.session,
                RequestReplay,
                RequestReplay.namespace == namespace,
                RequestReplay.idempotency_key == key,
            )
        )

    @staticmethod
    def _required(value: str, label: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise RequestControlError(f"{label} is required")
        return normalized

    def _tenant_id(self) -> str:
        tenant_id = self.session.info.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise RequestControlError("A validated tenant context is required")
        return tenant_id
