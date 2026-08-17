import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from athena.config import Settings


class GitHubCollectionError(RuntimeError):
    pass


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
        for repository in repositories:
            repo = self._required(repository, "name", "repository")
            for member in members:
                login = self._required(member, "login", "member")
                key = f"permission:{org}/{repo}:{login}"
                payload = self._single(
                    key, f"/repos/{org}/{repo}/collaborators/{login}/permission", cache
                )
                permission = self._required(payload, "permission", "permission")
                permissions.append(
                    {
                        "repository": repo,
                        "login": login,
                        "permission": permission,
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
                if not isinstance(payload, list):
                    raise GitHubCollectionError(
                        f"GitHub returned 304 without cached payload for {path}"
                    )
                return payload
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise GitHubCollectionError(f"GitHub response was not a list for {path}")
            first_page_etag = response.headers.get("etag")
            page = 2
            while "next" in response.links:
                response = self.client.get(response.links["next"]["url"], headers=self._headers())
                response.raise_for_status()
                next_payload = response.json()
                if not isinstance(next_payload, list):
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

    def _single(self, key: str, path: str, cache: dict) -> dict:
        cached = cache.get(key, {})
        try:
            response = self.client.get(
                f"{self.settings.github_api_url}{path}",
                headers=self._headers(cached.get("etag")),
            )
            if response.status_code == 304:
                payload = cached.get("payload")
            else:
                response.raise_for_status()
                payload = response.json()
                cache[key] = {"etag": response.headers.get("etag"), "payload": payload}
            if not isinstance(payload, dict):
                raise GitHubCollectionError(f"GitHub response was not an object for {path}")
            return payload
        except (httpx.HTTPError, ValueError) as error:
            raise GitHubCollectionError(f"GitHub request failed: GET {path}") from error

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
