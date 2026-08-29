import base64
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jwt.exceptions import InvalidTokenError

from athena.config import Settings
from athena.models import SecurityAgent
from athena.policy.opa import OpaClient, OpaDecision, OpaEvaluationError


class AgentAuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class AgentPrincipal:
    tenant_id: str
    agent_id: uuid.UUID
    agent_type: str
    capabilities: frozenset[str]


def canonical_digest(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_policy_signature(policy: dict, signature: str, public_key_pem: str) -> bool:
    try:
        key = load_pem_public_key(public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            return False
        encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        key.verify(base64.b64decode(signature, validate=True), encoded)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def create_enrollment_secret() -> tuple[str, str, str]:
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return secret, salt.hex(), digest.hex()


def verify_enrollment_secret(agent: SecurityAgent, supplied: str) -> bool:
    try:
        calculated = hashlib.scrypt(
            supplied.encode(),
            salt=bytes.fromhex(agent.credential_salt),
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        expected = bytes.fromhex(agent.credential_digest)
    except ValueError:
        return False
    return hmac.compare_digest(calculated, expected)


def issue_agent_token(agent: SecurityAgent, settings: Settings) -> tuple[str, datetime]:
    if not settings.security_agents_enabled:
        raise AgentAuthenticationError("Security agent authentication is disabled")
    secret = settings.security_agent_token_secret.get_secret_value()
    if len(secret) < 32:
        raise AgentAuthenticationError("Security agent authentication is not configured")
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=settings.security_agent_token_ttl_seconds)
    token = jwt.encode(
        {
            "iss": "athena-security-agents",
            "aud": "athena-security-events",
            "sub": str(agent.id),
            "tenant_id": agent.tenant_id,
            "agent_type": agent.agent_type,
            "capabilities": ["events:write", "policies:read"],
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": str(uuid.uuid4()),
        },
        secret,
        algorithm="HS256",
    )
    return token, expires


def verify_agent_token(token: str, settings: Settings) -> AgentPrincipal:
    try:
        if not settings.security_agents_enabled:
            raise InvalidTokenError("Agent authentication disabled")
        claims = jwt.decode(
            token,
            settings.security_agent_token_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="athena-security-events",
            issuer="athena-security-agents",
            options={"require": ["exp", "iat", "sub", "tenant_id", "agent_type", "jti"]},
        )
        capabilities = claims.get("capabilities")
        if not isinstance(capabilities, list) or not all(
            isinstance(capability, str) for capability in capabilities
        ):
            raise InvalidTokenError("Invalid capabilities")
        return AgentPrincipal(
            tenant_id=str(claims["tenant_id"]),
            agent_id=uuid.UUID(str(claims["sub"])),
            agent_type=str(claims["agent_type"]),
            capabilities=frozenset(capabilities),
        )
    except (InvalidTokenError, ValueError) as error:
        raise AgentAuthenticationError("Invalid or expired agent token") from error


class AgentActionPolicyError(RuntimeError):
    """Raised when the athena.security.agent_actions policy denies an event,
    or can't be evaluated at all. Carries `violations` so the route can
    return them; `violations` is empty for the OPA-unreachable case."""

    def __init__(self, message: str, violations: list[dict] | None = None) -> None:
        super().__init__(message)
        self.violations = violations or []


def evaluate_agent_action(settings: Settings, action: str, reason: str = "") -> OpaDecision:
    """Evaluates athena.security.agent_actions before an event is accepted.

    Only called for "allowed_override" by the route (see ingest_event) --
    every other action is already constrained to a fixed set by
    SecurityEventCreate's own Pydantic validator, so evaluating this policy
    for the common case (blocked/warned/quarantined) would just be a slower,
    redundant version of a check that already happened. `reason` is read
    from the agent's own evidence.override_reason convention by the caller
    -- there's no dedicated schema field for it today, only that informal
    convention (see SecurityEventCreate.evidence in schemas.py).

    Raises AgentActionPolicyError on either a real denial (violations
    populated) or an OPA-unreachable/malformed-response failure (violations
    empty) -- the route maps both to an HTTP error, just different codes.
    """
    client = OpaClient(settings.opa_url)
    client.policy_path = "athena/security/agent_actions/evaluate"
    try:
        with client:
            decision = client.evaluate({"action": action, "reason": reason})
    except OpaEvaluationError as error:
        raise AgentActionPolicyError(str(error)) from error
    if not decision.allow:
        raise AgentActionPolicyError(
            "Security event denied by agent_actions policy", decision.violations
        )
    return decision

