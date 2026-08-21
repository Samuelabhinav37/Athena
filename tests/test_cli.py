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
