from collections.abc import Generator

import pytest
from athena.database import get_db_session
from athena.main import app
from athena.models import Base, MonitoringRun, MonitoringStatus, MonitoringStep
from athena.services.monitoring import MonitoringError, MonitoringService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def monitoring_session() -> Generator[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        yield session
    engine.dispose()


def test_completed_schedule_slot_is_idempotent(monitoring_session: Session) -> None:
    calls = []

    def operation() -> dict:
        calls.append("called")
        return {"records": 6}

    service = MonitoringService(monitoring_session)
    first = service.run("hourly:20260816T2000", "scheduler", [("sync", operation)])
    second = service.run("hourly:20260816T2000", "scheduler", [("sync", operation)])

    assert first.status == MonitoringStatus.COMPLETED
    assert first.idempotent_replay is False
    assert second.idempotent_replay is True
    assert second.run_id == first.run_id
    assert calls == ["called"]
    assert len(monitoring_session.get(MonitoringRun, first.run_id).steps) == 1


def test_failed_slot_retains_evidence_and_retries_same_run(monitoring_session: Session) -> None:
    service = MonitoringService(monitoring_session)

    def fail() -> dict:
        raise RuntimeError("OPA unavailable")

    with pytest.raises(MonitoringError, match="policy failed"):
        service.run("hourly:20260816T2100", "scheduler", [("policy", fail)])
    run = monitoring_session.scalar(select(MonitoringRun))
    assert run is not None
    assert run.status == MonitoringStatus.FAILED
    assert run.attempt_count == 1
    assert run.steps[0].error == "RuntimeError: OPA unavailable"

    retried = service.run("hourly:20260816T2100", "scheduler", [("policy", lambda: {"failed": 0})])
    assert retried.run_id == run.id
    assert retried.status == MonitoringStatus.COMPLETED
    assert retried.attempt == 2
    assert [step.attempt for step in run.steps] == [1, 2]
    assert [step.status for step in run.steps] == [
        MonitoringStatus.FAILED,
        MonitoringStatus.COMPLETED,
    ]


def test_monitoring_steps_are_immutable(monitoring_session: Session) -> None:
    result = MonitoringService(monitoring_session).run(
        "daily:20260816", "scheduler", [("sync", lambda: {"records": 6})]
    )
    step = monitoring_session.scalar(
        select(MonitoringStep).where(MonitoringStep.run_id == result.run_id)
    )
    assert step is not None
    step.output = {"tampered": True}
    with pytest.raises(ValueError, match="immutable"):
        monitoring_session.commit()
    monitoring_session.rollback()


def test_monitoring_api_returns_ordered_step_evidence(monitoring_session: Session) -> None:
    result = MonitoringService(monitoring_session).run(
        "daily:20260817",
        "scheduler",
        [("sync", lambda: {"records": 6}), ("policy", lambda: {"failed": 1})],
    )

    def override_session() -> Generator[Session]:
        yield monitoring_session

    app.dependency_overrides[get_db_session] = override_session
    try:
        response = TestClient(app).get("/v1/monitoring/runs")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()[0]
    assert payload["id"] == str(result.run_id)
    assert payload["status"] == "completed"
    assert [step["name"] for step in payload["steps"]] == ["sync", "policy"]
