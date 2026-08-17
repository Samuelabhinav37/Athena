import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from athena.models import MonitoringRun, MonitoringStatus, MonitoringStep

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
    def __init__(self, session: Session) -> None:
        self.session = session

    def run(
        self, schedule_key: str, requested_by: str, operations: Sequence[Operation]
    ) -> MonitoringOutcome:
        if not schedule_key.strip():
            raise ValueError("schedule_key is required")
        run = self.session.scalar(
            select(MonitoringRun)
            .options(selectinload(MonitoringRun.steps))
            .where(MonitoringRun.schedule_key == schedule_key)
        )
        if run is not None and run.status == MonitoringStatus.COMPLETED:
            return self._outcome(run, True)
        if run is not None and run.status == MonitoringStatus.RUNNING:
            raise MonitoringError(f"Schedule slot {schedule_key} is already running")
        if run is None:
            run = MonitoringRun(
                schedule_key=schedule_key,
                status=MonitoringStatus.PENDING,
                requested_by=requested_by,
                summary={},
            )
            self.session.add(run)
            try:
                self.session.commit()
            except IntegrityError as error:
                self.session.rollback()
                raise MonitoringError(
                    f"Schedule slot {schedule_key} was claimed concurrently"
                ) from error
        run.status = MonitoringStatus.RUNNING
        run.attempt_count += 1
        run.started_at = datetime.now(UTC)
        run.completed_at = None
        run.error = None
        self.session.commit()
        outputs: dict[str, dict] = {}
        sequence = len(run.steps)
        for name, operation in operations:
            started = datetime.now(UTC)
            try:
                output = operation()
                step_status = MonitoringStatus.COMPLETED
                error_text = None
            except Exception as error:
                output = {}
                step_status = MonitoringStatus.FAILED
                error_text = f"{type(error).__name__}: {error}"
            sequence += 1
            step = MonitoringStep(
                sequence=sequence,
                attempt=run.attempt_count,
                name=name,
                status=step_status,
                started_at=started,
                completed_at=datetime.now(UTC),
                output=output,
                error=error_text,
            )
            run.steps.append(step)
            self.session.commit()
            if step_status == MonitoringStatus.FAILED:
                run.status = MonitoringStatus.FAILED
                run.completed_at = datetime.now(UTC)
                run.error = error_text
                run.summary = {"completed_steps": list(outputs), "failed_step": name}
                self.session.commit()
                raise MonitoringError(f"Monitoring step {name} failed: {error_text}")
            outputs[name] = output
        run.status = MonitoringStatus.COMPLETED
        run.completed_at = datetime.now(UTC)
        run.summary = {"completed_steps": list(outputs), "outputs": outputs}
        self.session.commit()
        return self._outcome(run, False)

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


def load_monitoring_runs(session: Session) -> list[MonitoringRun]:
    return list(
        session.scalars(
            select(MonitoringRun)
            .options(selectinload(MonitoringRun.steps))
            .order_by(MonitoringRun.started_at.desc())
        )
    )
