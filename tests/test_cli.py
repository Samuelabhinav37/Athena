import pytest
from athena import cli
from athena.collectors.keycloak import KeycloakCollectionError


def test_sync_command_reports_collection_failure_without_traceback(
    monkeypatch, capsys
) -> None:
    def fail_collection() -> None:
        raise KeycloakCollectionError("request failed without credentials")

    class FailingCollector:
        def __init__(self, *_: object) -> None:
            pass

        def __enter__(self) -> "FailingCollector":
            return self

        def __exit__(self, *_: object) -> None:
            pass

        collect = staticmethod(fail_collection)

    monkeypatch.setattr(cli, "KeycloakCollector", FailingCollector)
    monkeypatch.setattr(
        cli.ConnectorScopeRegistry,
        "require_approved",
        lambda *_: None,
    )

    assert cli.sync_keycloak("tenant-a") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "Keycloak synchronization failed: request failed without credentials\n"
    )
    assert "Traceback" not in captured.err


def test_tenant_inventory_command_dispatches_read_only_inventory(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["athena", "tenant-inventory"])
    monkeypatch.setattr(cli, "tenant_inventory", lambda: 17)

    assert cli.main() == 17


def test_tenant_backfill_plan_command_dispatches_approval_file(monkeypatch) -> None:
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["athena", "tenant-backfill-plan", "--approval-file", "approved.json"],
    )
    observed = None

    def plan(approval_file):
        nonlocal observed
        observed = approval_file
        return 19

    monkeypatch.setattr(cli, "tenant_backfill_plan", plan)

    assert cli.main() == 19
    assert observed == cli.Path("approved.json")


def test_tenant_backfill_command_requires_and_dispatches_plan_digest(monkeypatch) -> None:
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "athena",
            "tenant-backfill",
            "--approval-file",
            "approved.json",
            "--confirm-plan-sha256",
            "a" * 64,
        ],
    )
    observed = None

    def execute(approval_file, confirmed_plan_sha256):
        nonlocal observed
        observed = (approval_file, confirmed_plan_sha256)
        return 23

    monkeypatch.setattr(cli, "tenant_backfill", execute)

    assert cli.main() == 23
    assert observed == (cli.Path("approved.json"), "a" * 64)


def test_tenant_integrity_command_dispatches_read_only_inspection(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["athena", "tenant-integrity"])
    monkeypatch.setattr(cli, "tenant_integrity", lambda: 29)

    assert cli.main() == 29


def test_tenant_constraint_plan_command_dispatches_read_only_plan(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["athena", "tenant-constraint-plan"])
    monkeypatch.setattr(cli, "tenant_constraint_plan", lambda: 31)

    assert cli.main() == 31


def test_tenant_rls_plan_command_dispatches_read_only_plan(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["athena", "tenant-rls-plan"])
    monkeypatch.setattr(cli, "tenant_rls_plan", lambda: 37)

    assert cli.main() == 37


def test_tenant_scoped_command_requires_and_dispatches_explicit_tenant(monkeypatch) -> None:
    monkeypatch.setattr(cli, "sync_keycloak", lambda tenant_id: 41)
    monkeypatch.setattr(cli.sys, "argv", ["athena", "sync-keycloak"])
    with pytest.raises(SystemExit) as captured:
        cli.main()
    assert captured.value.code == 2

    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["athena", "sync-keycloak", "--tenant-id", "tenant-a"],
    )
    observed = None

    def synchronize(tenant_id: str) -> int:
        nonlocal observed
        observed = tenant_id
        return 41

    monkeypatch.setattr(cli, "sync_keycloak", synchronize)

    assert cli.main() == 41
    assert observed == "tenant-a"


def test_monitor_loop_retains_explicit_tenant_for_each_slot(monkeypatch) -> None:
    observed = None

    def monitor(tenant_id: str, username: str, schedule_key: str, requested_by: str) -> int:
        nonlocal observed
        observed = (tenant_id, username, schedule_key, requested_by)
        return 1

    monkeypatch.setattr(cli, "run_monitoring_slot", monitor)

    assert cli.monitoring_loop("tenant-a", "alice", 60, "scheduler") == 1
    assert observed is not None
    assert observed[0] == "tenant-a"
    assert observed[1] == "alice"
    assert observed[3] == "scheduler"


def test_job_session_factory_receives_only_the_explicit_tenant(monkeypatch, capsys) -> None:
    observed = None

    class Session:
        info = {"tenant_id": "tenant-b"}

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def scalar(self, *_: object):
            return None

    def factory(tenant_id: str):
        nonlocal observed
        observed = tenant_id
        return Session

    monkeypatch.setattr(cli, "get_session_factory", factory)

    assert cli.assess_risk("tenant-b", "alice") == 1
    assert observed == "tenant-b"
    assert "identity alice was not found" in capsys.readouterr().err
