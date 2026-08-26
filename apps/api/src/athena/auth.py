from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.config import Settings, get_settings
from athena.models import Identity
from athena.tenancy import TenantContext

VIEWER = "athena-viewer"
ANALYST = "athena-analyst"
REVIEWER = "athena-reviewer"
ADMINISTRATOR = "athena-administrator"
BREAK_GLASS = "athena-break-glass"

ROLE_LEVEL = {VIEWER: 1, ANALYST: 2, REVIEWER: 3, ADMINISTRATOR: 4, BREAK_GLASS: 4}
bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    roles: frozenset[str]
    claims: dict[str, Any]

    @property
    def actor(self) -> str:
        return self.username


class TokenVerifier:
    def __init__(
        self,
        settings: Settings,
        signing_key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        self.settings = settings
        jwks_url = settings.oidc_jwks_url.strip() or (
            f"{settings.oidc_issuer.rstrip('/')}/protocol/openid-connect/certs"
        )
        self.jwks = None if signing_key_resolver else PyJWKClient(jwks_url, cache_keys=True)
        self.signing_key_resolver = signing_key_resolver or self._resolve_jwks_key

    def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256":
                raise InvalidTokenError("Unexpected signing algorithm")
            if self.settings.oidc_require_key_id and not header.get("kid"):
                raise InvalidTokenError("Signing key ID is required")
            signing_key = self.signing_key_resolver(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer.rstrip("/"),
                leeway=self.settings.oidc_clock_skew_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
            issued_at = datetime.fromtimestamp(float(claims["iat"]), tz=UTC)
            expires_at = datetime.fromtimestamp(float(claims["exp"]), tz=UTC)
            if expires_at <= datetime.now(UTC):
                raise InvalidTokenError("Access token is expired")
            if datetime.now(UTC) - issued_at > timedelta(
                seconds=self.settings.oidc_max_token_age_seconds
                + self.settings.oidc_clock_skew_seconds
            ):
                raise InvalidTokenError("Access token is too old")
            roles = frozenset(_roles(claims, self.settings.oidc_audience))
            if BREAK_GLASS in roles:
                self._validate_break_glass(claims, issued_at, expires_at)
        except (InvalidTokenError, PyJWKClientError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from error
        subject = claims.get("sub")
        username = claims.get("preferred_username") or subject
        if not isinstance(subject, str) or not subject or not isinstance(username, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token is missing identity claims",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return Principal(
            subject,
            username,
            roles,
            claims,
        )

    def _validate_break_glass(
        self, claims: dict[str, Any], issued_at: datetime, expires_at: datetime
    ) -> None:
        reason = claims.get("athena_break_glass_reason")
        methods = claims.get("amr")
        if not self.settings.break_glass_enabled:
            raise InvalidTokenError("Break-glass access is disabled")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            raise InvalidTokenError("Break-glass token requires a token ID")
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidTokenError("Break-glass token requires a reason")
        if not isinstance(methods, list) or not {"hwk", "webauthn"}.intersection(methods):
            raise InvalidTokenError("Break-glass token requires hardware-backed authentication")
        if expires_at - issued_at > timedelta(seconds=self.settings.break_glass_max_token_seconds):
            raise InvalidTokenError("Break-glass token lifetime exceeds the configured maximum")

    def _resolve_jwks_key(self, token: str) -> Any:
        if self.jwks is None:  # pragma: no cover - constructor invariant
            raise ValueError("JWKS client is unavailable")
        return self.jwks.get_signing_key_from_jwt(token).key


def _roles(claims: dict[str, Any], audience: str) -> set[str]:
    roles = set()
    realm_access = claims.get("realm_access", {})
    if isinstance(realm_access, dict) and isinstance(realm_access.get("roles"), list):
        roles.update(role for role in realm_access["roles"] if isinstance(role, str))
    resource_access = claims.get("resource_access", {})
    if isinstance(resource_access, dict):
        api_access = resource_access.get(audience, {})
        if isinstance(api_access, dict) and isinstance(api_access.get("roles"), list):
            roles.update(role for role in api_access["roles"] if isinstance(role, str))
    return roles


@lru_cache
def get_token_verifier() -> TokenVerifier:
    return TokenVerifier(get_settings())


def get_current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)],
) -> Principal:
    if not settings.auth_required:
        return Principal("local-auth-disabled", "test-user", frozenset(ROLE_LEVEL), {})
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verifier.verify(credentials.credentials)


def get_tenant_context(
    principal: Annotated[Principal, Depends(get_current_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TenantContext:
    if not settings.auth_required:
        return TenantContext(
            tenant_id=settings.system_tenant_id,
            subject=principal.subject,
            source="system_job",
        )
    tenant_id = principal.claims.get("athena_tenant_id")
    if not isinstance(tenant_id, str):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access token is missing a valid Athena tenant claim",
        )
    try:
        return TenantContext(
            tenant_id=tenant_id,
            subject=principal.subject,
            source="oidc_claim",
        )
    except ValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access token is missing a valid Athena tenant claim",
        ) from error


def authorize_tenant_membership(
    principal: Principal,
    context: TenantContext,
    settings: Settings,
    session: Session,
) -> None:
    if not settings.auth_required:
        return
    identity_id = session.scalar(
        select(Identity.id).where(
            Identity.tenant_id == context.tenant_id,
            Identity.source == settings.oidc_identity_source,
            Identity.external_id == principal.subject,
            Identity.active.is_(True),
        )
    )
    if identity_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated identity is not an active member of the requested tenant",
        )


def authorize(principal: Principal, required_role: str) -> Principal:
    required_level = ROLE_LEVEL[required_role]
    granted_level = max((ROLE_LEVEL.get(role, 0) for role in principal.roles), default=0)
    if granted_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {required_role} or higher is required",
        )
    return principal


def require_viewer(principal: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
    return authorize(principal, VIEWER)


def require_analyst(principal: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
    return authorize(principal, ANALYST)


def require_reviewer(principal: Annotated[Principal, Depends(get_current_principal)]) -> Principal:
    return authorize(principal, REVIEWER)


def require_administrator(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> Principal:
    return authorize(principal, ADMINISTRATOR)


ViewerPrincipal = Annotated[Principal, Depends(require_viewer)]
AnalystPrincipal = Annotated[Principal, Depends(require_analyst)]
ReviewerPrincipal = Annotated[Principal, Depends(require_reviewer)]
AdministratorPrincipal = Annotated[Principal, Depends(require_administrator)]
