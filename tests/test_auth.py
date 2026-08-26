from datetime import UTC, datetime, timedelta

import jwt
import pytest
from athena.auth import (
    Principal,
    TokenVerifier,
    ViewerPrincipal,
    authorize,
    authorize_tenant_membership,
    get_tenant_context,
)
from athena.config import Settings
from athena.models import AuditEvent, Base, Identity, IdentityType, Tenant
from athena.tenancy import TenantContext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker


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


def test_verifier_rejects_missing_key_id_and_stale_token(keys: tuple[bytes, bytes]) -> None:
    private_key, public_key = keys
    now = datetime.now(UTC)
    claims = {
        "sub": "user-charlie",
        "iss": "http://keycloak.test/realms/athena",
        "aud": "athena-api",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    missing_kid = jwt.encode(claims, private_key, algorithm="RS256")
    with pytest.raises(HTTPException):
        verifier(public_key).verify(missing_kid)

    stale = token(
        private_key,
        iat=now - timedelta(hours=2),
        exp=now + timedelta(minutes=5),
    )
    with pytest.raises(HTTPException):
        verifier(public_key).verify(stale)


def test_break_glass_is_disabled_by_default_and_requires_hardware_authentication(
    keys: tuple[bytes, bytes],
) -> None:
    private_key, public_key = keys
    break_glass_claims = {
        "realm_access": {"roles": ["athena-break-glass"]},
        "jti": "emergency-1",
        "athena_break_glass_reason": "Restore tenant administration",
        "amr": ["webauthn"],
    }
    with pytest.raises(HTTPException):
        verifier(public_key).verify(token(private_key, **break_glass_claims))

    settings = Settings(
        database_url="sqlite://",
        oidc_issuer="http://keycloak.test/realms/athena",
        oidc_audience="athena-api",
        break_glass_enabled=True,
    )
    enabled = TokenVerifier(settings, signing_key_resolver=lambda _: public_key)
    principal = enabled.verify(token(private_key, **break_glass_claims))
    assert authorize(principal, "athena-administrator") is principal

    with pytest.raises(HTTPException):
        enabled.verify(token(private_key, **(break_glass_claims | {"amr": ["pwd"]})))


def test_break_glass_database_access_appends_audit_evidence(monkeypatch) -> None:
    from athena.database import get_db_session

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, info={"tenant_id": "tenant-a"})
    settings = Settings(database_url="sqlite://", auth_required=True, break_glass_enabled=True)
    principal = Principal(
        "subject-1",
        "emergency-admin",
        frozenset({"athena-break-glass"}),
        {
            "jti": "emergency-1",
            "amr": ["webauthn"],
            "athena_break_glass_reason": "Restore administration",
        },
    )
    context = TenantContext(tenant_id="tenant-a", subject="subject-1", source="oidc_claim")
    with factory.begin() as session:
        session.add_all(
            [
                Tenant(
                    id="tenant-a",
                    display_name="Tenant A",
                    approval_reference="test",
                    authorized_by="test",
                    approved_at=datetime.now(UTC),
                    inventory_sha256="0" * 64,
                ),
                Identity(
                    tenant_id="tenant-a",
                    source="keycloak",
                    external_id="subject-1",
                    username="emergency-admin",
                    identity_type=IdentityType.HUMAN,
                    display_name="Emergency Admin",
                    active=True,
                    source_metadata={},
                ),
            ]
        )
    monkeypatch.setattr("athena.database.get_session_factory", lambda _: factory)

    dependency = get_db_session(context, principal, settings)
    next(dependency)
    dependency.close()

    with factory() as session:
        event = session.scalar(select(AuditEvent))
        assert event is not None
        assert event.action == "break_glass_tenant_access"
        assert event.approval["token_id"] == "emergency-1"
    engine.dispose()


def test_role_hierarchy_allows_higher_roles_and_denies_lower_roles() -> None:
    analyst = Principal("analyst-id", "bob", frozenset({"athena-analyst"}), {})
    viewer = Principal("viewer-id", "alice", frozenset({"athena-viewer"}), {})

    assert authorize(analyst, "athena-viewer") is analyst
    with pytest.raises(HTTPException) as captured:
        authorize(viewer, "athena-reviewer")
    assert captured.value.status_code == 403


def test_tenant_context_requires_valid_signed_claim() -> None:
    settings = Settings(database_url="sqlite://", auth_required=True)
    principal = Principal(
        "user-charlie",
        "charlie",
        frozenset({"athena-viewer"}),
        {"athena_tenant_id": "tenant-a"},
    )

    context = get_tenant_context(principal, settings)

    assert context.tenant_id == "tenant-a"
    assert context.subject == "user-charlie"
    assert context.source == "oidc_claim"

    for claims in ({}, {"athena_tenant_id": "INVALID TENANT"}):
        with pytest.raises(HTTPException) as captured:
            get_tenant_context(Principal("user-charlie", "charlie", frozenset(), claims), settings)
        assert captured.value.status_code == 403


def test_auth_disabled_uses_explicit_system_tenant() -> None:
    settings = Settings(
        database_url="sqlite://", auth_required=False, system_tenant_id="local-test"
    )
    principal = Principal("local-auth-disabled", "test-user", frozenset(), {})

    context = get_tenant_context(principal, settings)

    assert context.tenant_id == "local-test"
    assert context.source == "system_job"


def test_tenant_membership_requires_active_subject_in_claimed_tenant() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = Settings(database_url="sqlite://", auth_required=True)
    principal = Principal("subject-1", "charlie", frozenset(), {})
    claimed_tenant = TenantContext(
        tenant_id="tenant-a", subject=principal.subject, source="oidc_claim"
    )

    with Session(engine) as session:
        session.add_all(
            [
                Identity(
                    tenant_id="tenant-a",
                    source="keycloak",
                    external_id="subject-1",
                    username="charlie",
                    identity_type=IdentityType.HUMAN,
                    display_name="Charlie",
                    active=True,
                    source_metadata={},
                ),
                Identity(
                    tenant_id="tenant-b",
                    source="keycloak",
                    external_id="other-subject",
                    username="other",
                    identity_type=IdentityType.HUMAN,
                    display_name="Other",
                    active=True,
                    source_metadata={},
                ),
            ]
        )
        session.flush()

        authorize_tenant_membership(principal, claimed_tenant, settings, session)

        for tenant_id, subject in (
            ("tenant-b", "subject-1"),
            ("tenant-a", "unknown-subject"),
        ):
            with pytest.raises(HTTPException) as captured:
                authorize_tenant_membership(
                    Principal(subject, subject, frozenset(), {}),
                    TenantContext(tenant_id=tenant_id, subject=subject, source="oidc_claim"),
                    settings,
                    session,
                )
            assert captured.value.status_code == 403

        session.query(Identity).filter_by(external_id="subject-1").update({"active": False})
        with pytest.raises(HTTPException) as captured:
            authorize_tenant_membership(principal, claimed_tenant, settings, session)
        assert captured.value.status_code == 403


def test_tenant_membership_uses_configured_trusted_oidc_identity_source() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    settings = Settings(
        database_url="sqlite://",
        auth_required=True,
        oidc_identity_source="azure_entra",
    )
    principal = Principal("entra-object-1", "alice", frozenset(), {})
    context = TenantContext(tenant_id="tenant-a", subject=principal.subject, source="oidc_claim")

    with Session(engine) as session:
        session.add(
            Identity(
                tenant_id="tenant-a",
                source="azure_entra",
                external_id=principal.subject,
                username="alice@example.test",
                identity_type=IdentityType.HUMAN,
                display_name="Alice",
                active=True,
                source_metadata={},
            )
        )
        session.flush()

        authorize_tenant_membership(principal, context, settings, session)


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
    accepted = client.get("/protected", headers={"Authorization": f"Bearer {token(private_key)}"})

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert accepted.status_code == 200
    assert accepted.json() == {"actor": "charlie"}
