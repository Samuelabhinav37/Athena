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

    assert set(users) == EXPECTED_USERS
    assert users["alice"]["attributes"]["department"] == ["engineering"]
    assert users["alice"]["realmRoles"] == ["developer"]
    assert users["alice"]["groups"] == ["/departments/engineering"]


def test_every_user_has_governance_attributes_and_temporary_credentials() -> None:
    for user in load_realm()["users"]:
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

    assert set(clients) == {"athena-api", "athena-web"}
    assert clients["athena-api"]["bearerOnly"] is True
    assert clients["athena-web"]["publicClient"] is True
    assert clients["athena-web"]["attributes"]["pkce.code.challenge.method"] == "S256"
    assert all(client["directAccessGrantsEnabled"] is False for client in clients.values())
