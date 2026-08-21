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

    assert cli.sync_keycloak() == 1
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
