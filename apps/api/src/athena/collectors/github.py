import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from athena.collectors.contracts import (
    CapabilitySupport,
    ConnectorCapability,
    ConnectorCapabilityDeclaration,
    ConnectorManifest,
)
from athena.config import Settings


class GitHubCollectionError(RuntimeError):
    pass


def _manifest(
    connector_id: str,
    display_name: str,
    provider: str,
    declarations: dict[ConnectorCapability, tuple[str, str]],
) -> ConnectorManifest:
    return ConnectorManifest(
        connector_id=connector_id,
        display_name=display_name,
        provider=provider,
        capabilities={
            capability: ConnectorCapabilityDeclaration(
                support=CapabilitySupport(support), detail=detail
            )
            for capability, (support, detail) in declarations.items()
        },
    )


@dataclass(frozen=True)
class GitHubSnapshot:
    organization: str
    members: list[dict]
    repositories: list[dict]
    permissions: list[dict]
    endpoint_cache: dict
    fingerprint: str
    teams: list[dict] = field(default_factory=list)
    team_memberships: list[dict] = field(default_factory=list)


class GitHubCollector:
    @classmethod
    def manifest(cls) -> ConnectorManifest:
        declarations = {
            ConnectorCapability.IDENTITY_DISCOVERY: ("supported", "Collects organization members."),
            ConnectorCapability.PAGINATION: ("supported", "Follows GitHub REST pagination."),
            ConnectorCapability.INCREMENTAL_CURSORS: (
                "partial",
                "Uses endpoint ETags but has no provider-wide change cursor.",
            ),
            ConnectorCapability.RETRIES: (
                "unsupported",
                "Fails closed on request errors; retry orchestration is external.",
            ),
            ConnectorCapability.COLLECTION_FRESHNESS: (
                "partial",
                "Synchronization records observation time outside the collector snapshot.",
            ),
            ConnectorCapability.AUTHORIZATION_INHERITANCE: (
                "partial",
                "Collects teams and calculated effective permissions without complete "
                "grant lineage.",
            ),
            ConnectorCapability.NESTED_GROUPS: (
                "unsupported",
                "Does not collect or resolve parent-team relationships.",
            ),
            ConnectorCapability.DENY_RULES: (
                "unsupported",
                "GitHub organization collection does not expose explicit deny rules.",
            ),
            ConnectorCapability.PRIVILEGED_ELIGIBILITY: (
                "unsupported",
                "Does not collect time-bound privileged eligibility.",
            ),
            ConnectorCapability.MACHINE_IDENTITIES: (
                "unsupported",
                "Collects organization members and does not inventory GitHub Apps or bots.",
            ),
            ConnectorCapability.ACTIVITY_SIGNALS: (
                "unsupported",
                "Does not collect audit-log or last-used activity signals.",
            ),
        }
        return _manifest("github", "GitHub organization", "GitHub", declarations)

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(timeout=httpx.Timeout(20.0))
        self._owns_client = client is None

    def __enter__(self) -> "GitHubCollector":
        return self

    def __exit__(self, *_: object) -> None:
        if self._owns_client:
            self.client.close()

    def collect(self, endpoint_cache: dict | None = None) -> GitHubSnapshot:
        org = self.settings.github_org.strip()
        token = self.settings.github_token.get_secret_value()
        if not org or not token:
            raise GitHubCollectionError("GitHub organization and token are required")
        cache = dict(endpoint_cache or {})
        members = self._paged(f"org:{org}:members", f"/orgs/{org}/members", cache)
        repositories = self._paged(f"org:{org}:repos", f"/orgs/{org}/repos", cache)
        teams = self._paged(f"org:{org}:teams", f"/orgs/{org}/teams", cache)
        team_memberships = []
        for team in teams:
            slug = self._required(team, "slug", "team")
            team_members = self._paged(
                f"team:{org}/{slug}:members", f"/orgs/{org}/teams/{slug}/members", cache
            )
            team_memberships.extend(
                {
                    "team_id": team["id"],
                    "team_slug": slug,
                    "login": self._required(member, "login", "team member"),
                }
                for member in team_members
            )
        permissions = []
        member_logins = {self._required(member, "login", "member") for member in members}
        for repository in repositories:
            repo = self._required(repository, "name", "repository")
            collaborators = self._paged(
                f"repo:{org}/{repo}:collaborators",
                f"/repos/{org}/{repo}/collaborators",
                cache,
            )
            for collaborator in collaborators:
                login = self._required(collaborator, "login", "collaborator")
                if login not in member_logins:
                    continue
                permissions.append(
                    {
                        "repository": repo,
                        "login": login,
                        "permission": self._collaborator_permission(collaborator),
                        "source": "calculated",
                    }
                )
        canonical = json.dumps(
            {
                "members": members,
                "repositories": repositories,
                "permissions": permissions,
                "teams": teams,
                "team_memberships": team_memberships,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return GitHubSnapshot(
            org,
            members,
            repositories,
            permissions,
            cache,
            hashlib.sha256(canonical.encode()).hexdigest(),
            teams,
            team_memberships,
        )

    def _paged(self, key: str, path: str, cache: dict) -> list[dict]:
        cached = cache.get(key, {})
        etag = cached.get("etag") if cached.get("pages", 1) == 1 else None
        headers = self._headers(etag)
        try:
            response = self.client.get(
                f"{self.settings.github_api_url}{path}",
                headers=headers,
                params={"per_page": 100, "page": 1},
            )
            if response.status_code == 304:
                payload = cached.get("payload")
                if not etag or not isinstance(payload, list) or not all(
                    isinstance(item, dict) for item in payload
                ):
                    raise GitHubCollectionError(
                        f"GitHub returned 304 without cached payload for {path}"
                    )
                return payload
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
                raise GitHubCollectionError(f"GitHub response was not a list for {path}")
            first_page_etag = response.headers.get("etag")
            page = 2
            visited = {str(response.request.url)}
            while "next" in response.links:
                next_url = httpx.URL(response.links["next"]["url"])
                initial = httpx.URL(f"{self.settings.github_api_url}{path}")
                if (
                    (next_url.scheme, next_url.host, next_url.port, next_url.path)
                    != (initial.scheme, initial.host, initial.port, initial.path)
                    or next_url.userinfo or next_url.fragment
                ):
                    raise GitHubCollectionError("GitHub pagination left its trusted endpoint")
                if str(next_url) in visited or len(visited) >= 10000:
                    raise GitHubCollectionError("GitHub pagination repeated or exceeded its limit")
                visited.add(str(next_url))
                response = self.client.get(next_url, headers=self._headers())
                response.raise_for_status()
                next_payload = response.json()
                if not isinstance(next_payload, list) or not all(
                    isinstance(item, dict) for item in next_payload
                ):
                    raise GitHubCollectionError(f"GitHub page was not a list for {path}")
                payload.extend(next_payload)
                page += 1
            cache[key] = {
                "etag": first_page_etag,
                "payload": payload,
                "pages": page - 1,
            }
            return payload
        except (httpx.HTTPError, ValueError) as error:
            raise GitHubCollectionError(f"GitHub request failed: GET {path}") from error

    @staticmethod
    def _collaborator_permission(collaborator: dict[str, Any]) -> str:
        role_name = collaborator.get("role_name")
        if isinstance(role_name, str) and role_name:
            return role_name
        permissions = collaborator.get("permissions")
        if not isinstance(permissions, dict):
            raise GitHubCollectionError("GitHub collaborator is missing permission evidence")
        for name in ("admin", "maintain", "push", "triage", "pull"):
            if permissions.get(name) is True:
                return name
        raise GitHubCollectionError("GitHub collaborator has no recognized permission")

    def _headers(self, etag: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.settings.github_token.get_secret_value()}",
            "X-GitHub-Api-Version": self.settings.github_api_version,
        }
        if etag:
            headers["If-None-Match"] = etag
        return headers

    @staticmethod
    def _required(payload: dict[str, Any], key: str, subject: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise GitHubCollectionError(f"GitHub {subject} is missing required field {key}")
        return value
