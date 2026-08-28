import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from athena.models import MonitoringRun, MonitoringStatus, MonitoringStep
from athena.tenant_queries import tenant_select

Operation = tuple[str, Callable[[], dict]]


class MonitoringError(RuntimeError):
    pass


@dataclass(frozen=True)
class MonitoringOutcome:
    run_id: uuid.UUID
    schedule_key: str
    status: MonitoringStatus
    attempt: int
    steps_completed: int
    idempotent_replay: bool


class MonitoringService:
    def __init__(
        self,
        session: Session,
        *,
        clock: Callable[[], datetime] | None = None,
        lease_duration: timedelta = timedelta(minutes=15),
    ) -> None:
        if lease_duration < timedelta(minutes=1):
            raise ValueError("Monitoring lease duration must be at least one minute")
        self.session = session
        self.clock = clock or (lambda: datetime.now(UTC))
        self.lease_duration = lease_duration

    def run(
        self, schedule_key: str, requested_by: str, operations: Sequence[Operation]
    ) -> MonitoringOutcome:
        if not schedule_key.strip():
            raise ValueError("schedule_key is required")
        now = self._now()
        statement = (
            tenant_select(self.session, MonitoringRun, MonitoringRun.schedule_key == schedule_key)
            .options(selectinload(MonitoringRun.steps))
            .with_for_update()
        )
        run = self.session.scalar(statement)
        if run is not None and run.status == MonitoringStatus.COMPLETED:
            return self._outcome(run, True)
        stale_lease = run is not None and run.status == MonitoringStatus.RUNNING
        if stale_lease and self._aware(run.lease_expires_at) is not None and self._aware(
            run.lease_expires_at
        ) > now:
            raise MonitoringError(f"Schedule slot {schedule_key} is already running")
        if run is None:
            run = MonitoringRun(
                schedule_key=schedule_key,
                status=MonitoringStatus.PENDING,
                attempt_count=0,
                requested_by=requested_by,
                summary={},
            )
            self.session.add(run)
        elif stale_lease:
            run.steps.append(
                MonitoringStep(
                    sequence=len(run.steps) + 1,
                    attempt=run.attempt_count,
                    name="lease_recovery",
                    status=MonitoringStatus.FAILED,
                    started_at=run.heartbeat_at or run.started_at or now,
                    completed_at=now,
                    output={
                        "lease_expired_at": (
                            run.lease_expires_at.isoformat() if run.lease_expires_at else None
                        )
                    },
                    error="Monitoring lease expired before the run reached a terminal state",
                )
            )
        lease_token = uuid.uuid4()
        run.status = MonitoringStatus.RUNNING
        run.attempt_count += 1
        run.started_at = now
        run.completed_at = None
        run.error = None
        run.lease_token = lease_token
        run.heartbeat_at = now
        run.lease_expires_at = now + self.lease_duration
        try:
            self.session.commit()
        except IntegrityError as error:
            self.session.rollback()
            raise MonitoringError(
                f"Schedule slot {schedule_key} was claimed concurrently"
            ) from error
        outputs: dict[str, dict] = {}
        sequence = len(run.steps)
        run_id = run.id
        attempt = run.attempt_count
        for name, operation in operations:
            started = self._heartbeat(run_id, lease_token)
            try:
                output = operation()
                step_status = MonitoringStatus.COMPLETED
                error_text = None
            except Exception as error:
                self.session.rollback()
                run = self._owned_run(run_id, lease_token, error)
                output = {}
                step_status = MonitoringStatus.FAILED
                error_text = f"{type(error).__name__}: {error}"
            else:
                self._heartbeat(run_id, lease_token)
            sequence += 1
            step = MonitoringStep(
                sequence=sequence,
                attempt=attempt,
                name=name,
                status=step_status,
                started_at=started,
                completed_at=self._now(),
                output=output,
                error=error_text,
            )
            run.steps.append(step)
            if step_status == MonitoringStatus.FAILED:
                run.status = MonitoringStatus.FAILED
                run.completed_at = self._now()
                run.error = error_text
                run.summary = {"completed_steps": list(outputs), "failed_step": name}
                run.lease_token = None
                run.lease_expires_at = None
                self.session.commit()
                raise MonitoringError(f"Monitoring step {name} failed: {error_text}")
            self.session.commit()
            outputs[name] = output
        run = self._owned_run(run_id, lease_token)
        run.status = MonitoringStatus.COMPLETED
        run.completed_at = self._now()
        run.summary = {"completed_steps": list(outputs), "outputs": outputs}
        run.lease_token = None
        run.lease_expires_at = None
        self.session.commit()
        return self._outcome(run, False)

    def _heartbeat(self, run_id: uuid.UUID, lease_token: uuid.UUID) -> datetime:
        now = self._now()
        result = self.session.execute(
            update(MonitoringRun)
            .where(
                MonitoringRun.id == run_id,
                MonitoringRun.lease_token == lease_token,
                MonitoringRun.status == MonitoringStatus.RUNNING,
            )
            .values(heartbeat_at=now, lease_expires_at=now + self.lease_duration)
        )
        if result.rowcount != 1:
            self.session.rollback()
            raise MonitoringError(f"Monitoring lease for run {run_id} was lost")
        self.session.commit()
        return now

    def _owned_run(
        self,
        run_id: uuid.UUID,
        lease_token: uuid.UUID,
        cause: Exception | None = None,
    ) -> MonitoringRun:
        run = self.session.scalar(
            tenant_select(
                self.session,
                MonitoringRun,
                MonitoringRun.id == run_id,
                MonitoringRun.lease_token == lease_token,
            ).options(selectinload(MonitoringRun.steps))
        )
        if run is None:
            error = MonitoringError(f"Monitoring lease for run {run_id} was lost")
            if cause is not None:
                raise error from cause
            raise error
        return run

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Monitoring clock must return a timezone-aware datetime")
        return value

    @staticmethod
    def _aware(value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    @staticmethod
    def _outcome(run: MonitoringRun, replay: bool) -> MonitoringOutcome:
        return MonitoringOutcome(
            run.id,
            run.schedule_key,
            run.status,
            run.attempt_count,
            sum(step.status == MonitoringStatus.COMPLETED for step in run.steps),
            replay,
        )


def load_monitoring_runs(
    session: Session, *, limit: int | None = None, offset: int = 0
) -> list[MonitoringRun]:
    statement = (
        tenant_select(session, MonitoringRun)
        .options(selectinload(MonitoringRun.steps))
        .order_by(MonitoringRun.started_at.desc())
        .offset(offset)
    )
    if limit is not None:
        statement = statement.limit(limit)
    return list(session.scalars(statement))
