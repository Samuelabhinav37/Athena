import httpx
import pytest
from athena.collectors.azure import AzureCollectionError, AzureCollector
from athena.collectors.github import GitHubCollectionError, GitHubCollector
from athena.config import Settings


@pytest.mark.parametrize("provider", ["github", "azure"])
def test_empty_page_with_continuation_is_not_end_of_inventory(provider: str) -> None:
    calls = []
    root = "https://api.github.test" if provider == "github" else "https://graph.microsoft.com"
    path = "/orgs/acme/members" if provider == "github" else "/v1.0/users"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        page = [{"id": "last-account"}] if len(calls) == 2 else []
        if provider == "github":
            headers = {"Link": f'<{root}{path}?page=2>; rel="next"'} if len(calls) == 1 else {}
            return httpx.Response(200, json=page, headers=headers)
        payload = {"value": page}
        if len(calls) == 1:
            payload["@odata.nextLink"] = f"{root}{path}?page=2"
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        if provider == "github":
            collector = GitHubCollector(Settings(
                database_url="sqlite://", github_api_url=root,
                github_org="acme", github_token="synthetic-token",
            ), client)
            result = collector._paged("members", path, {})
        else:
            collector = AzureCollector(Settings(
                database_url="sqlite://", azure_tenant_id="synthetic",
                azure_subscription_id="synthetic",
            ), credential=object(), client=client)
            result = collector._pages(root, path, {}, "@odata.nextLink")
    assert result == [{"id": "last-account"}]
    assert len(calls) == 2


@pytest.mark.parametrize("target", [
    "https://untrusted.test/collect",
    "http://api.github.test/orgs/acme/members?page=2",
    "https://api.github.test/orgs/other/members?page=2",
    "https://api.github.test:8443/orgs/acme/members?page=2",
])
def test_github_rejects_changed_pagination_destination_before_request(target: str) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert len(calls) == 1, "Untrusted continuation was requested"
        return httpx.Response(200, json=[], headers={"Link": f'<{target}>; rel="next"'})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        collector = GitHubCollector(Settings(
            database_url="sqlite://", github_api_url="https://api.github.test",
            github_org="acme", github_token="synthetic-token",
        ), client)
        with pytest.raises(GitHubCollectionError, match="trusted endpoint"):
            collector.collect()
    assert len(calls) == 1


@pytest.mark.parametrize("provider", ["github", "azure"])
@pytest.mark.parametrize("failure", ["cycle", "malformed", "http_error"])
def test_incomplete_pagination_never_returns_a_snapshot(provider: str, failure: str) -> None:
    calls = []
    url = "https://api.github.test/orgs/acme/members?page=2" if provider == "github" else (
        "https://graph.microsoft.com/v1.0/users?page=2"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert len(calls) <= 2, "Pagination loop was not bounded"
        if len(calls) == 2 and failure == "http_error":
            return httpx.Response(503)
        if len(calls) == 2 and failure == "malformed":
            return httpx.Response(200, json=["not-an-object"])
        if provider == "github":
            return httpx.Response(200, json=[], headers={"Link": f'<{url}>; rel="next"'})
        return httpx.Response(200, json={"value": [], "@odata.nextLink": url})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        if provider == "github":
            collector = GitHubCollector(Settings(
                database_url="sqlite://", github_api_url="https://api.github.test",
                github_org="acme", github_token="synthetic-token",
            ), client)
            cache = {"existing": {"payload": [{"id": "preserved"}]}}
            with pytest.raises(GitHubCollectionError):
                collector.collect(cache)
            assert cache == {"existing": {"payload": [{"id": "preserved"}]}}
        else:
            collector = AzureCollector(Settings(
                database_url="sqlite://", azure_tenant_id="synthetic",
                azure_subscription_id="synthetic",
            ), credential=object(), client=client)
            with pytest.raises((AzureCollectionError, httpx.HTTPStatusError)):
                collector._pages(
                    "https://graph.microsoft.com", "/v1.0/users", {}, "@odata.nextLink"
                )
    assert len(calls) == 2
