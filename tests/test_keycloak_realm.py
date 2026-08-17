import json
from pathlib import Path

REALM_PATH = Path(__file__).parents[1] / "infra" / "keycloak" / "realm-athena.json"
EXPECTED_USERS = {"alice", "bob", "charlie", "david", "emma", "frank"}
EXPECTED_DEPARTMENTS = {"engineering", "finance", "hr", "security", "devops", "it"}


def load_realm() -> dict:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def test_realm_has_expected_security_defaults() -> None:
    realm = load_realm()

    assert realm["realm"] == "athena"
    assert realm["enabled"] is True
    assert realm["registrationAllowed"] is False
    assert realm["bruteForceProtected"] is True


def test_realm_contains_ground_truth_users() -> None:
    users = {user["username"]: user for user in load_realm()["users"]}

    assert set(users) >= EXPECTED_USERS
    assert users["alice"]["attributes"]["department"] == ["engineering"]
    assert users["alice"]["realmRoles"] == ["developer", "athena-viewer"]
    assert users["alice"]["groups"] == ["/departments/engineering"]


def test_every_user_has_governance_attributes_and_temporary_credentials() -> None:
    for user in load_realm()["users"]:
        if user.get("serviceAccountClientId"):
            continue
        assert user["enabled"] is True
        assert user["emailVerified"] is True
        assert user["attributes"]["department"]
        assert user["attributes"]["job_title"]
        assert user["attributes"]["employment_status"] == ["active"]
        assert user["groups"]
        assert user["realmRoles"]
        assert user["credentials"]
        assert all(credential["temporary"] is True for credential in user["credentials"])


def test_realm_contains_expected_departments() -> None:
    department_root = next(
        group for group in load_realm()["groups"] if group["name"] == "departments"
    )
    departments = {group["name"] for group in department_root["subGroups"]}

    assert departments == EXPECTED_DEPARTMENTS


def test_client_configuration_does_not_enable_password_grants() -> None:
    clients = {client["clientId"]: client for client in load_realm()["clients"]}

    assert set(clients) == {"athena-api", "athena-collector", "athena-web"}
    assert clients["athena-api"]["bearerOnly"] is True
    assert clients["athena-web"]["publicClient"] is True
    assert clients["athena-web"]["attributes"]["pkce.code.challenge.method"] == "S256"
    assert all(client["directAccessGrantsEnabled"] is False for client in clients.values())
    audience = next(
        mapper
        for mapper in clients["athena-web"]["protocolMappers"]
        if mapper["name"] == "athena-api-audience"
    )
    assert audience["config"]["included.client.audience"] == "athena-api"


def test_realm_defines_composite_api_roles() -> None:
    roles = {role["name"]: role for role in load_realm()["roles"]["realm"]}

    assert roles["athena-analyst"]["composites"]["realm"] == ["athena-viewer"]
    assert roles["athena-reviewer"]["composites"]["realm"] == ["athena-analyst"]
    assert roles["athena-administrator"]["composites"]["realm"] == ["athena-reviewer"]


def test_collector_uses_a_dedicated_read_only_service_account() -> None:
    realm = load_realm()
    clients = {client["clientId"]: client for client in realm["clients"]}
    service_user = next(
        user
        for user in realm["users"]
        if user.get("serviceAccountClientId") == "athena-collector"
    )

    assert clients["athena-collector"]["serviceAccountsEnabled"] is True
    assert clients["athena-collector"]["standardFlowEnabled"] is False
    assert clients["athena-collector"]["fullScopeAllowed"] is True
    assert set(service_user["clientRoles"]["realm-management"]) == {
        "query-groups",
        "query-users",
        "view-realm",
        "view-users",
    }
