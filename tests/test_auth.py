from datetime import UTC, datetime, timedelta

import jwt
import pytest
from athena.auth import Principal, TokenVerifier, ViewerPrincipal, authorize
from athena.config import Settings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def keys() -> tuple[bytes, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def token(private_key: bytes, **overrides: object) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": "user-charlie",
        "preferred_username": "charlie",
        "iss": "http://keycloak.test/realms/athena",
        "aud": "athena-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "realm_access": {"roles": ["athena-viewer"]},
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


def verifier(public_key: bytes) -> TokenVerifier:
    settings = Settings(
        database_url="sqlite://",
        oidc_issuer="http://keycloak.test/realms/athena",
        oidc_audience="athena-api",
    )
    return TokenVerifier(settings, signing_key_resolver=lambda _: public_key)


def test_verifier_validates_signature_issuer_audience_and_roles(keys: tuple[bytes, bytes]) -> None:
    private_key, public_key = keys

    principal = verifier(public_key).verify(token(private_key))

    assert principal.subject == "user-charlie"
    assert principal.actor == "charlie"
    assert principal.roles == frozenset({"athena-viewer"})


@pytest.mark.parametrize(
    "claim,value",
    [
        ("aud", "another-api"),
        ("iss", "http://attacker.test/realms/athena"),
        ("exp", datetime.now(UTC) - timedelta(seconds=1)),
    ],
)
def test_verifier_rejects_invalid_security_claims(
    keys: tuple[bytes, bytes], claim: str, value: object
) -> None:
    private_key, public_key = keys

    with pytest.raises(HTTPException) as captured:
        verifier(public_key).verify(token(private_key, **{claim: value}))

    assert captured.value.status_code == 401


def test_role_hierarchy_allows_higher_roles_and_denies_lower_roles() -> None:
    analyst = Principal("analyst-id", "bob", frozenset({"athena-analyst"}), {})
    viewer = Principal("viewer-id", "alice", frozenset({"athena-viewer"}), {})

    assert authorize(analyst, "athena-viewer") is analyst
    with pytest.raises(HTTPException) as captured:
        authorize(viewer, "athena-reviewer")
    assert captured.value.status_code == 403


def test_protected_route_requires_bearer_token(keys: tuple[bytes, bytes]) -> None:
    private_key, public_key = keys
    application = FastAPI()
    settings = Settings(
        database_url="sqlite://",
        auth_required=True,
        oidc_issuer="http://keycloak.test/realms/athena",
        oidc_audience="athena-api",
    )
    token_verifier = TokenVerifier(settings, signing_key_resolver=lambda _: public_key)

    from athena.auth import get_settings, get_token_verifier

    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_token_verifier] = lambda: token_verifier

    @application.get("/protected")
    def protected(principal: ViewerPrincipal) -> dict:
        return {"actor": principal.actor}

    client = TestClient(application)
    missing = client.get("/protected")
    accepted = client.get(
        "/protected", headers={"Authorization": f"Bearer {token(private_key)}"}
    )

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert accepted.status_code == 200
    assert accepted.json() == {"actor": "charlie"}
