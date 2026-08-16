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
