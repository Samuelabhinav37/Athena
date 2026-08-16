import httpx
from athena.collectors.keycloak import KeycloakCollector
from athena.config import Settings


def test_collector_normalizes_humans_and_excludes_service_accounts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            assert "client_secret=collector-secret" in request.content.decode()
            return httpx.Response(200, json={"access_token": "test-token"})
        assert request.headers["Authorization"] == "Bearer test-token"
        if path.endswith("/users"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "user-alice",
                        "username": "alice",
                        "firstName": "Alice",
                        "lastName": "Johnson",
                        "email": "alice@acme.test",
                        "emailVerified": True,
                        "enabled": True,
                        "attributes": {
                            "department": ["engineering"],
                            "job_title": ["Developer"],
                            "manager": ["bob"],
                        },
                    },
                    {
                        "id": "service-user",
                        "username": "service-account-athena-collector",
                        "serviceAccountClientId": "athena-collector",
                    },
                ],
            )
        if path.endswith("/users/user-alice/groups"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "group-engineering",
                        "name": "engineering",
                        "path": "/departments/engineering",
                    }
                ],
            )
        if path.endswith("/users/user-alice/role-mappings/realm"):
            return httpx.Response(
                200,
                json=[
                    {"id": "role-developer", "name": "developer", "description": "Developer"},
                    {"id": "role-default", "name": "default-roles-athena"},
                ],
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    settings = Settings(
        database_url="sqlite://",
        keycloak_url="http://keycloak.test",
        keycloak_client_secret="collector-secret",
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        records = KeycloakCollector(settings, client).collect()

    assert len(records) == 1
    assert records[0].username == "alice"
    assert records[0].department == "engineering"
    assert [group.name for group in records[0].groups] == ["engineering"]
    assert [role.name for role in records[0].roles] == ["developer"]
