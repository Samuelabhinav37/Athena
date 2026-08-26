from collections.abc import Iterator
from typing import Any

import httpx

from athena.collectors.contracts import (
    CapabilitySupport,
    ConnectorCapability,
    ConnectorCapabilityDeclaration,
    ConnectorManifest,
    NormalizedGroup,
    NormalizedIdentity,
    NormalizedRole,
)
from athena.config import Settings
from athena.models import IdentityType

INTERNAL_REALM_ROLES = {"offline_access", "uma_authorization"}


class KeycloakCollectionError(RuntimeError):
    """Raised when Keycloak cannot provide a complete, trustworthy snapshot."""


class KeycloakCollector:
    @classmethod
    def manifest(cls) -> ConnectorManifest:
        declarations = {
            ConnectorCapability.IDENTITY_DISCOVERY: ("supported", "Collects realm human users."),
            ConnectorCapability.PAGINATION: (
                "supported",
                "Uses bounded offset pagination for users.",
            ),
            ConnectorCapability.INCREMENTAL_CURSORS: (
                "unsupported",
                "Performs full collection and has no change cursor.",
            ),
            ConnectorCapability.RETRIES: (
                "unsupported",
                "Fails closed on request errors; retry orchestration is external.",
            ),
            ConnectorCapability.COLLECTION_FRESHNESS: (
                "unsupported",
                "The collector result does not carry an observation timestamp.",
            ),
            ConnectorCapability.AUTHORIZATION_INHERITANCE: (
                "partial",
                "Collects current realm roles and groups without complete grant lineage.",
            ),
            ConnectorCapability.NESTED_GROUPS: (
                "partial",
                "Preserves group paths but does not emit a nested-group relationship graph.",
            ),
            ConnectorCapability.DENY_RULES: (
                "unsupported",
                "Does not collect Keycloak authorization-service deny policies.",
            ),
            ConnectorCapability.PRIVILEGED_ELIGIBILITY: (
                "unsupported",
                "Does not collect time-bound privileged eligibility.",
            ),
            ConnectorCapability.MACHINE_IDENTITIES: (
                "unsupported",
                "Explicitly excludes Keycloak service-account users from this snapshot.",
            ),
            ConnectorCapability.ACTIVITY_SIGNALS: (
                "unsupported",
                "Does not collect login events or last-used activity.",
            ),
        }
        return ConnectorManifest(
            connector_id="keycloak",
            display_name="Keycloak realm",
            provider="Keycloak",
            capabilities={
                capability: ConnectorCapabilityDeclaration(
                    support=CapabilitySupport(support), detail=detail
                )
                for capability, (support, detail) in declarations.items()
            },
        )

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(timeout=httpx.Timeout(10.0))
        self._owns_client = client is None

    def __enter__(self) -> "KeycloakCollector":
        return self

    def __exit__(self, *_: object) -> None:
        if self._owns_client:
            self.client.close()

    def collect(self) -> list[NormalizedIdentity]:
        token = self._access_token()
        headers = {"Authorization": f"Bearer {token}"}
        identities = []
        for user in self._users(headers):
            if user.get("serviceAccountClientId"):
                continue
            identities.append(self._normalize_user(user, headers))
        return identities

    def _access_token(self) -> str:
        url = (
            f"{self.settings.keycloak_url}/realms/{self.settings.keycloak_realm}"
            "/protocol/openid-connect/token"
        )
        payload = self._request(
            "POST",
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.settings.keycloak_client_id,
                "client_secret": self.settings.keycloak_client_secret.get_secret_value(),
            },
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise KeycloakCollectionError("Keycloak token response did not contain an access token")
        return token

    def _users(self, headers: dict[str, str]) -> Iterator[dict[str, Any]]:
        first = 0
        page_size = 100
        while True:
            page = self._request(
                "GET",
                self._admin_url("users"),
                headers=headers,
                params={"first": first, "max": page_size},
            )
            if not isinstance(page, list):
                raise KeycloakCollectionError("Keycloak users response was not a list")
            yield from page
            if len(page) < page_size:
                return
            first += page_size

    def _normalize_user(
        self, user: dict[str, Any], headers: dict[str, str]
    ) -> NormalizedIdentity:
        user_id = self._required_string(user, "id", "user")
        username = self._required_string(user, "username", "user")
        groups_payload = self._request(
            "GET", self._admin_url(f"users/{user_id}/groups"), headers=headers
        )
        roles_payload = self._request(
            "GET", self._admin_url(f"users/{user_id}/role-mappings/realm"), headers=headers
        )
        if not isinstance(groups_payload, list) or not isinstance(roles_payload, list):
            raise KeycloakCollectionError(f"Incomplete membership response for user {username}")

        first_name = str(user.get("firstName", "")).strip()
        last_name = str(user.get("lastName", "")).strip()
        display_name = " ".join(part for part in (first_name, last_name) if part) or username
        attributes = user.get("attributes") or {}

        return NormalizedIdentity(
            source="keycloak",
            external_id=user_id,
            username=username,
            identity_type=IdentityType.HUMAN,
            display_name=display_name,
            email=user.get("email"),
            department=self._first_attribute(attributes, "department"),
            job_title=self._first_attribute(attributes, "job_title"),
            manager_external_id=self._first_attribute(attributes, "manager"),
            active=bool(user.get("enabled", False)),
            source_metadata={"email_verified": bool(user.get("emailVerified", False))},
            groups=[
                NormalizedGroup(
                    external_id=self._required_string(group, "id", "group"),
                    name=self._required_string(group, "name", "group"),
                    path=self._required_string(group, "path", "group"),
                )
                for group in groups_payload
            ],
            roles=[
                NormalizedRole(
                    external_id=self._required_string(role, "id", "role"),
                    name=self._required_string(role, "name", "role"),
                    description=role.get("description"),
                )
                for role in roles_payload
                if not self._is_internal_role(role)
            ],
        )

    def _admin_url(self, path: str) -> str:
        return (
            f"{self.settings.keycloak_url}/admin/realms/"
            f"{self.settings.keycloak_realm}/{path}"
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            response = self.client.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise KeycloakCollectionError(
                f"Keycloak request failed: {method} {url}"
            ) from error

    @staticmethod
    def _first_attribute(attributes: dict[str, Any], name: str) -> str | None:
        values = attributes.get(name)
        if isinstance(values, list) and values and isinstance(values[0], str):
            return values[0]
        return None

    @staticmethod
    def _required_string(payload: dict[str, Any], key: str, subject: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise KeycloakCollectionError(f"Keycloak {subject} is missing required field {key}")
        return value

    def _is_internal_role(self, role: dict[str, Any]) -> bool:
        name = role.get("name")
        return name in INTERNAL_REALM_ROLES or (
            isinstance(name, str) and name.startswith("default-roles-")
        )
