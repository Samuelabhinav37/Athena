from collections.abc import Generator

import httpx
from athena.collectors.github import GitHubCollector, GitHubSnapshot
from athena.config import Settings
from athena.database import get_db_session
from athena.main import app
from athena.models import AccessGrant, Base, ConnectorCheckpoint, EffectiveEntitlement, Identity
from athena.services.github_sync import GitHubSyncService
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def settings() -> Settings:
    return Settings(
        database_url="sqlite://",
        github_api_url="https://api.github.test",
        github_org="acme",
        github_token="read-only-token",
    )


def test_collector_uses_versioned_read_only_requests_and_etag_cache() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer read-only-token"
        assert request.headers["X-GitHub-Api-Version"] == "2026-03-10"
        if request.headers.get("If-None-Match"):
            return httpx.Response(304)
        path = request.url.path
        if path.endswith("/orgs/acme/members"):
            return httpx.Response(
                200,
                headers={"ETag": '"members-v1"'},
                json=[
                    {
                        "id": 101,
                        "login": "octocat",
                        "node_id": "U_101",
                        "html_url": "https://github.com/octocat",
                    }
                ],
            )
        if path.endswith("/orgs/acme/repos"):
            return httpx.Response(
                200,
                headers={"ETag": '"repos-v1"'},
                json=[
                    {
                        "id": 201,
                        "name": "athena",
                        "full_name": "acme/athena",
                        "private": True,
                        "visibility": "private",
                        "archived": False,
                    }
                ],
            )
        if path.endswith("/orgs/acme/teams"):
            return httpx.Response(
                200,
                headers={"ETag": '"teams-v1"'},
                json=[{"id": 301, "name": "Security", "slug": "security"}],
            )
        if path.endswith("/orgs/acme/teams/security/members"):
            return httpx.Response(
                200, headers={"ETag": '"team-members-v1"'}, json=[{"id": 101, "login": "octocat"}]
            )
        if path.endswith("/repos/acme/athena/collaborators/octocat/permission"):
            return httpx.Response(
                200, headers={"ETag": '"permission-v1"'}, json={"permission": "admin"}
            )
        raise AssertionError(f"Unexpected request {request.url}")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        collector = GitHubCollector(settings(), client)
        first = collector.collect()
        second = collector.collect(first.endpoint_cache)

    assert first.fingerprint == second.fingerprint
    assert first.permissions == [
        {"repository": "athena", "login": "octocat", "permission": "admin", "source": "calculated"}
    ]
    assert first.team_memberships == [{"team_id": 301, "team_slug": "security", "login": "octocat"}]
    assert len(calls) == 10
    assert sum(request.headers.get("If-None-Match") is not None for request in calls) == 5


def test_multi_page_endpoints_are_refetched_to_avoid_stale_later_pages() -> None:
    member_requests = []
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/members") and "/teams/" not in path:
            member_requests.append(request)
            if request.url.params.get("page") == "2":
                return httpx.Response(200, json=[])
            return httpx.Response(
                200,
                headers={
                    "ETag": '"members-page-1"',
                    "Link": '<https://api.github.test/orgs/acme/members?page=2>; rel="next"',
                },
                json=[{"id": 101, "login": "octocat"}],
            )
        if path.endswith("/repos") or path.endswith("/teams"):
            return httpx.Response(200, json=[])
        raise AssertionError(f"Unexpected request {request.url}")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        collector = GitHubCollector(settings(), client)
        first = collector.collect()
        collector.collect(first.endpoint_cache)
    assert first.endpoint_cache["org:acme:members"]["pages"] == 2
    assert len(member_requests) == 4
    assert all(request.headers.get("If-None-Match") is None for request in member_requests)


def test_sync_materializes_effective_permission_and_revokes_missing_access() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    initial = GitHubSnapshot(
        organization="acme",
        members=[{"id": 101, "login": "octocat", "node_id": "U_101"}],
        repositories=[
            {
                "id": 201,
                "name": "athena",
                "full_name": "acme/athena",
                "private": True,
                "visibility": "private",
                "archived": False,
            }
        ],
        permissions=[
            {
                "repository": "athena",
                "login": "octocat",
                "permission": "admin",
                "source": "calculated",
            }
        ],
        endpoint_cache={"org:acme:members": {"etag": '"v1"'}},
        fingerprint="a" * 64,
        teams=[{"id": 301, "name": "Security", "slug": "security"}],
        team_memberships=[{"team_id": 301, "team_slug": "security", "login": "octocat"}],
    )
    with factory() as session:
        service = GitHubSyncService(session)
        first = service.sync(initial)
        second = service.sync(initial)
        grant = session.scalar(select(AccessGrant).where(AccessGrant.source == "github"))
        entitlement = session.scalar(select(EffectiveEntitlement))
        checkpoint = session.scalar(select(ConnectorCheckpoint))
        identity = session.scalar(select(Identity).where(Identity.username == "octocat"))
        assert grant is not None and entitlement is not None and checkpoint is not None
        assert identity is not None
        assert first.grants_created == 1
        assert second.unchanged is True
        assert grant.permission.privileged is True
        assert grant.source_metadata["lineage_complete"] is False
        assert entitlement.provenance_edges[0].relationship_type == "reported_effective_permission"
        assert sorted(group.name for group in identity.groups) == ["Security", "acme"]

        removed = GitHubSnapshot(
            organization="acme",
            members=initial.members,
            repositories=initial.repositories,
            permissions=[],
            endpoint_cache={},
            fingerprint="b" * 64,
        )
        result = service.sync(removed)
        assert result.grants_revoked == 1
        assert grant.revoked_at is not None
        assert entitlement.active is False
    engine.dispose()


def test_connector_api_exposes_checkpoint_without_cached_payload() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        session.add(
            ConnectorCheckpoint(
                connector="github",
                scope="acme",
                fingerprint="c" * 64,
                endpoint_cache={"members": {"payload": [{"login": "private-user"}]}},
            )
        )
        session.commit()

        def override_session() -> Generator:
            yield session

        app.dependency_overrides[get_db_session] = override_session
        try:
            response = TestClient(app).get("/v1/connectors")
        finally:
            app.dependency_overrides.clear()
        assert response.status_code == 200
        payload = response.json()[0]
        assert payload["id"] == str(session.scalar(select(ConnectorCheckpoint.id)))
        assert payload["connector"] == "github"
        assert payload["scope"] == "acme"
        assert payload["fingerprint"] == "c" * 64
        assert payload["cached_endpoints"] == 1
        assert "private-user" not in response.text
    engine.dispose()
