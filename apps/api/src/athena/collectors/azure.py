import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential

from athena.collectors.contracts import (
    CapabilitySupport,
    ConnectorCapability,
    ConnectorCapabilityDeclaration,
    ConnectorManifest,
)
from athena.config import Settings


class AzureCollectionError(RuntimeError):
    pass


class TokenCredential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class AzureSnapshot:
    tenant_id: str
    subscription_id: str
    users: list[dict]
    groups: list[dict]
    group_members: dict[str, list[str]]
    service_principals: list[dict]
    role_assignments: list[dict]
    role_definitions: list[dict]
    endpoint_cache: dict
    fingerprint: str


class AzureCollector:
    """Collect Microsoft Entra and Azure RBAC evidence through read-only APIs."""

    @classmethod
    def manifest(cls) -> ConnectorManifest:
        declarations = {
            ConnectorCapability.IDENTITY_DISCOVERY: (
                "supported",
                "Collects Entra users and groups.",
            ),
            ConnectorCapability.PAGINATION: (
                "supported",
                "Follows trusted Microsoft pagination links.",
            ),
            ConnectorCapability.INCREMENTAL_CURSORS: (
                "unsupported",
                "Performs full snapshots and does not consume Microsoft delta cursors.",
            ),
            ConnectorCapability.RETRIES: (
                "unsupported",
                "Fails closed on API errors; retry orchestration is external.",
            ),
            ConnectorCapability.COLLECTION_FRESHNESS: (
                "partial",
                "Synchronization records observation time outside the collector snapshot.",
            ),
            ConnectorCapability.AUTHORIZATION_INHERITANCE: (
                "partial",
                "Preserves RBAC scopes but does not expand every inherited effective permission.",
            ),
            ConnectorCapability.NESTED_GROUPS: (
                "partial",
                "Collects direct group member IDs without recursively resolving nesting.",
            ),
            ConnectorCapability.DENY_RULES: (
                "unsupported",
                "Does not collect Azure deny assignments.",
            ),
            ConnectorCapability.PRIVILEGED_ELIGIBILITY: (
                "unsupported",
                "Does not collect Microsoft Entra PIM eligibility schedules.",
            ),
            ConnectorCapability.MACHINE_IDENTITIES: (
                "supported",
                "Collects service principals, managed identity type, owners, and credentials.",
            ),
            ConnectorCapability.ACTIVITY_SIGNALS: (
                "unsupported",
                "Does not collect sign-in or resource activity logs.",
            ),
        }
        return ConnectorManifest(
            connector_id="azure",
            display_name="Microsoft Entra ID and Azure RBAC",
            provider="Microsoft Azure",
            capabilities={
                capability: ConnectorCapabilityDeclaration(
                    support=CapabilitySupport(support), detail=detail
                )
                for capability, (support, detail) in declarations.items()
            },
        )

    def __init__(
        self,
        settings: Settings,
        credential: TokenCredential | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not settings.azure_tenant_id.strip() or not settings.azure_subscription_id.strip():
            raise AzureCollectionError("Azure tenant and subscription IDs are required")
        self.settings = settings
        self.credential = credential or DefaultAzureCredential()
        self._owns_credential = credential is None
        self.client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None

    def __enter__(self) -> "AzureCollector":
        return self

    def __exit__(self, *_: object) -> None:
        if self._owns_client:
            self.client.close()
        if self._owns_credential:
            self.credential.close()

    def collect(self, _endpoint_cache: dict | None = None) -> AzureSnapshot:
        try:
            graph_headers = self._headers("https://graph.microsoft.com/.default")
            management_headers = self._headers("https://management.azure.com/.default")
            users = self._pages(
                self.settings.azure_graph_url,
                "/v1.0/users?$select=id,userPrincipalName,displayName,accountEnabled,department,jobTitle,mail",
                graph_headers,
                "@odata.nextLink",
            )
            groups = self._pages(
                self.settings.azure_graph_url,
                "/v1.0/groups?$select=id,displayName,description",
                graph_headers,
                "@odata.nextLink",
            )
            service_principals = self._pages(
                self.settings.azure_graph_url,
                "/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials",
                graph_headers,
                "@odata.nextLink",
            )
            for principal in service_principals:
                principal["AthenaOwners"] = self._pages(
                    self.settings.azure_graph_url,
                    f"/v1.0/servicePrincipals/{principal['id']}/owners?$select=id,displayName,userPrincipalName",
                    graph_headers,
                    "@odata.nextLink",
                )
            group_members = {
                group["id"]: [
                    member["id"]
                    for member in self._pages(
                        self.settings.azure_graph_url,
                        f"/v1.0/groups/{group['id']}/members?$select=id",
                        graph_headers,
                        "@odata.nextLink",
                    )
                ]
                for group in groups
            }
            scope = f"/subscriptions/{self.settings.azure_subscription_id}"
            role_assignments = self._pages(
                self.settings.azure_management_url,
                f"{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
                management_headers,
                "nextLink",
            )
            role_definitions = self._pages(
                self.settings.azure_management_url,
                f"{scope}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01",
                management_headers,
                "nextLink",
            )
        except (AzureError, httpx.HTTPError, KeyError, TypeError, ValueError) as error:
            raise AzureCollectionError("Azure read-only collection failed") from error
        users = sorted(users, key=lambda item: item["id"])
        groups = sorted(groups, key=lambda item: item["id"])
        service_principals = sorted(service_principals, key=lambda item: item["id"])
        role_assignments = sorted(role_assignments, key=lambda item: item["id"])
        role_definitions = sorted(role_definitions, key=lambda item: item["id"])
        group_members = {key: sorted(value) for key, value in sorted(group_members.items())}
        inventory = {
            "users": users,
            "groups": groups,
            "group_members": group_members,
            "service_principals": service_principals,
            "role_assignments": role_assignments,
            "role_definitions": role_definitions,
        }
        canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        cache = {
            "inventory": {
                "fingerprint": fingerprint,
                "counts": {
                    "users": len(users),
                    "groups": len(groups),
                    "service_principals": len(service_principals),
                    "role_assignments": len(role_assignments),
                    "role_definitions": len(role_definitions),
                },
            }
        }
        return AzureSnapshot(
            self.settings.azure_tenant_id,
            self.settings.azure_subscription_id,
            users,
            groups,
            group_members,
            service_principals,
            role_assignments,
            role_definitions,
            cache,
            fingerprint,
        )

    def _headers(self, scope: str) -> dict[str, str]:
        token = self.credential.get_token(scope)
        token_value = getattr(token, "token", None)
        if not isinstance(token_value, str) or not token_value:
            raise AzureCollectionError("Azure credential returned no access token")
        return {"Authorization": f"Bearer {token_value}", "Accept": "application/json"}

    def _pages(
        self, base_url: str, path: str, headers: dict[str, str], next_key: str
    ) -> list[dict]:
        root = base_url.rstrip("/")
        url = f"{root}{path}"
        values: list[dict] = []
        while url:
            response = self.client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()
            page = payload.get("value")
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                raise AzureCollectionError("Azure collection response value was not an object list")
            values.extend(page)
            next_url = payload.get(next_key)
            if next_url is None:
                break
            if not isinstance(next_url, str) or not next_url.startswith(f"{root}/"):
                raise AzureCollectionError("Azure pagination attempted to leave its trusted API")
            url = next_url
        return values
