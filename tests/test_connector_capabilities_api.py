from athena.auth import Principal, get_current_principal
from athena.collectors.azure import AzureCollector
from athena.collectors.github import GitHubCollector
from athena.collectors.keycloak import KeycloakCollector
from athena.routes.connectors import router
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_viewer_can_read_capabilities_without_initializing_collectors(monkeypatch) -> None:
    def forbid_collection(*args, **kwargs):
        raise AssertionError("Capability discovery must not initialize a live collector")

    for collector in (AzureCollector, GitHubCollector, KeycloakCollector):
        monkeypatch.setattr(collector, "__init__", forbid_collection)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "viewer", "viewer", frozenset({"athena-viewer"}), {}
    )
    with TestClient(app) as client:
        response = client.get("/v1/connectors/capabilities")
    assert response.status_code == 200
    manifests = {item["connector_id"]: item for item in response.json()}
    assert set(manifests) == {"azure", "github", "keycloak"}
    assert manifests["azure"]["capabilities"]["deny_rules"]["support"] == "unsupported"
    assert all(item["read_only"] for item in manifests.values())
    assert all(item["data_authority"] == "evidence_only" for item in manifests.values())
    assert "endpoint_cache" not in response.text


def test_capabilities_require_viewer_role() -> None:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "unprivileged", "unprivileged", frozenset(), {}
    )
    with TestClient(app) as client:
        assert client.get("/v1/connectors/capabilities").status_code == 403
