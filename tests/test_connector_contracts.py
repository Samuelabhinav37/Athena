import json

import pytest
from athena.collectors.azure import AzureCollector
from athena.collectors.contracts import (
    CapabilitySupport,
    ConnectorCapability,
    ConnectorCapabilityDeclaration,
    ConnectorManifest,
    IAMConnector,
)
from athena.collectors.github import GitHubCollector
from athena.collectors.keycloak import KeycloakCollector
from pydantic import ValidationError


@pytest.mark.parametrize("collector", [GitHubCollector, AzureCollector, KeycloakCollector])
def test_connector_manifest_conformance(collector: type[IAMConnector]) -> None:
    manifest = collector.manifest()

    assert manifest.contract_version == "1.0"
    assert manifest.read_only is True
    assert manifest.data_authority == "evidence_only"
    assert set(manifest.capabilities) == set(ConnectorCapability)
    assert "token" not in json.dumps(manifest.model_dump(mode="json")).lower()


def test_manifests_state_known_provider_limitations_honestly() -> None:
    github = GitHubCollector.manifest().capabilities
    azure = AzureCollector.manifest().capabilities
    keycloak = KeycloakCollector.manifest().capabilities

    assert github[ConnectorCapability.INCREMENTAL_CURSORS].support is CapabilitySupport.PARTIAL
    assert azure[ConnectorCapability.MACHINE_IDENTITIES].support is CapabilitySupport.SUPPORTED
    assert (
        azure[ConnectorCapability.PRIVILEGED_ELIGIBILITY].support
        is CapabilitySupport.UNSUPPORTED
    )
    assert keycloak[ConnectorCapability.MACHINE_IDENTITIES].support is CapabilitySupport.UNSUPPORTED


def test_manifest_rejects_write_authority_and_incomplete_capabilities() -> None:
    declaration = ConnectorCapabilityDeclaration(
        support=CapabilitySupport.SUPPORTED, detail="Supported for this connector."
    )

    with pytest.raises(ValidationError, match="read_only"):
        ConnectorManifest(
            connector_id="unsafe",
            display_name="Unsafe",
            provider="Unsafe",
            read_only=False,
            capabilities={capability: declaration for capability in ConnectorCapability},
        )
    with pytest.raises(ValidationError, match="missing capabilities"):
        ConnectorManifest(
            connector_id="incomplete",
            display_name="Incomplete",
            provider="Incomplete",
            capabilities={ConnectorCapability.IDENTITY_DISCOVERY: declaration},
        )
