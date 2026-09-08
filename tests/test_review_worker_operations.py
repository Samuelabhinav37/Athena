import json
from contextlib import nullcontext
from unittest.mock import Mock

from athena import cli
from sqlalchemy.exc import SQLAlchemyError


def test_worker_sweep_emits_alert_and_updates_heartbeat(monkeypatch, tmp_path, capsys):
    session = object()
    monkeypatch.setattr(cli, "get_session_factory", lambda tenant: lambda: nullcontext(session))
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    worker = Mock()
    worker.run_once.return_value = {
        "attempted": 1,
        "verification_recorded": 0,
        "failed": 1,
        "deferred": 3,
        "exhausted": 2,
        "scan_complete": True,
    }
    monkeypatch.setattr(cli, "ReviewRetryWorker", lambda *args: worker)
    heartbeat = tmp_path / "heartbeat"
    assert cli.retry_review_collection("tenant-a", 100, heartbeat) == 1
    event = json.loads(capsys.readouterr().out)
    assert event["event"] == "review_worker_sweep"
    assert event["tenant_id"] == "tenant-a"
    assert event["alerts"] == ["collection_failed", "retry_exhausted"]
    assert event["scan_complete"] is True
    assert heartbeat.exists()


def test_worker_database_error_is_sanitized_and_does_not_refresh_heartbeat(
    monkeypatch,
    tmp_path,
    capsys,
):
    def unavailable(*args):
        raise SQLAlchemyError("synthetic-sensitive-connection-string")

    monkeypatch.setattr(cli, "get_session_factory", unavailable)
    heartbeat = tmp_path / "heartbeat"
    assert cli.retry_review_collection("tenant-a", 100, heartbeat) == 1
    output = capsys.readouterr().out
    assert "synthetic-sensitive" not in output
    assert json.loads(output)["code"] == "service_unavailable"
    assert not heartbeat.exists()


def test_worker_heartbeat_write_failure_is_observable(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "get_session_factory", lambda tenant: lambda: nullcontext(object()))
    monkeypatch.setattr(cli, "get_settings", lambda: object())
    worker = Mock()
    worker.run_once.return_value = {"failed": 0, "exhausted": 0, "scan_complete": True}
    monkeypatch.setattr(cli, "ReviewRetryWorker", lambda *args: worker)
    assert cli.retry_review_collection("tenant-a", 100, tmp_path / "absent" / "heartbeat") == 1
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[-1]["code"] == "heartbeat_unavailable"
