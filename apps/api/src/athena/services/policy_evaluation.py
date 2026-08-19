import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AccessGrant,
    EffectiveEntitlement,
    Identity,
    PolicyDecision,
    PolicyEvaluation,
)
from athena.policy.contracts import (
    CanonicalPolicyRequest,
    PolicyAction,
    PolicyAuthenticationContext,
    PolicyGovernanceContext,
    PolicyPrincipal,
    PolicyProvenanceEdge,
    PolicyRequestContext,
    PolicyResource,
)
from athena.policy.opa import OpaDecision, OpaEvaluationError
from athena.services.provenance import governance_gaps


class PolicyEngine(Protocol):
    policy_path: str

    def evaluate(self, policy_input: CanonicalPolicyRequest) -> OpaDecision: ...


@dataclass(frozen=True)
class EvaluationSummary:
    passed: int
    failed: int
    errors: int
    policy_version: str


def hash_policy_bundle(policy_directory: Path) -> str:
    policy_files = sorted(
        path
        for path in policy_directory.rglob("*.rego")
        if not path.name.endswith("_test.rego")
    )
    if not policy_files:
        raise FileNotFoundError(f"No Rego policies found in {policy_directory}")
    digest = hashlib.sha256()
    for path in policy_files:
        digest.update(path.relative_to(policy_directory).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class PolicyEvaluationService:
    def __init__(
        self,
        session: Session,
        engine: PolicyEngine,
        policy_directory: Path,
    ) -> None:
        self.session = session
        self.engine = engine
        self.policy_version = hash_policy_bundle(policy_directory)

    def evaluate_identity(self, identity: Identity) -> EvaluationSummary:
        entitlements = list(
            self.session.scalars(
                select(EffectiveEntitlement)
                .options(
                    selectinload(EffectiveEntitlement.provenance_edges),
                    selectinload(EffectiveEntitlement.grant).selectinload(
                        AccessGrant.approved_by
                    ),
                    selectinload(EffectiveEntitlement.grant).selectinload(
                        AccessGrant.requested_by
                    ),
                )
                .where(
                    EffectiveEntitlement.identity_id == identity.id,
                    EffectiveEntitlement.active.is_(True),
                )
            ).unique()
        )
        counts = {PolicyDecision.PASS: 0, PolicyDecision.FAIL: 0, PolicyDecision.ERROR: 0}
        for entitlement in entitlements:
            policy_input = self._request(identity, entitlement)
            try:
                result = self.engine.evaluate(policy_input)
                decision = PolicyDecision.PASS if result.allow else PolicyDecision.FAIL
                violations = result.violations
            except OpaEvaluationError as error:
                decision = PolicyDecision.ERROR
                violations = [
                    {
                        "code": "POLICY_ENGINE_UNAVAILABLE",
                        "severity": "critical",
                        "rule": "policy_engine_must_return_a_valid_decision",
                        "message": str(error),
                        "evidence": {},
                    }
                ]
            self.session.add(
                PolicyEvaluation(
                    entitlement_id=entitlement.id,
                    engine="opa",
                    policy_path=self.engine.policy_path,
                    policy_version=self.policy_version,
                    decision=decision,
                    input_snapshot=policy_input.model_dump(mode="json"),
                    violations=violations,
                )
            )
            counts[decision] += 1
        self.session.commit()
        return EvaluationSummary(
            passed=counts[PolicyDecision.PASS],
            failed=counts[PolicyDecision.FAIL],
            errors=counts[PolicyDecision.ERROR],
            policy_version=self.policy_version,
        )

    @staticmethod
    def _request(
        identity: Identity, entitlement: EffectiveEntitlement
    ) -> CanonicalPolicyRequest:
        grant = entitlement.grant
        permission = entitlement.permission
        resource = permission.resource
        authentication = identity.source_metadata.get("authentication", {})
        if not isinstance(authentication, dict):
            authentication = {}
        return CanonicalPolicyRequest(
            principal=PolicyPrincipal(
                id=str(identity.id),
                type=identity.identity_type.value,
                username=identity.username,
                department=identity.department,
                roles=tuple(sorted(role.name for role in identity.roles)),
                groups=tuple(sorted(group.path for group in identity.groups)),
            ),
            action=PolicyAction(
                id=str(permission.id),
                verb=permission.action,
                name=permission.name,
                privileged=permission.privileged,
            ),
            resource=PolicyResource(
                id=str(resource.id),
                external_id=resource.external_id,
                name=resource.name,
                type=resource.resource_type.value,
                sensitivity=resource.sensitivity.value,
            ),
            context=PolicyRequestContext(
                governance=PolicyGovernanceContext(
                    gaps=tuple(governance_gaps(grant)),
                    requested_by=grant.requested_by.username if grant.requested_by else None,
                    approved_by=grant.approved_by.username if grant.approved_by else None,
                    business_reason=grant.business_reason,
                    policy_reference=grant.policy_reference,
                    granted_at=grant.granted_at.isoformat(),
                    expires_at=grant.expires_at.isoformat() if grant.expires_at else None,
                ),
                authentication=PolicyAuthenticationContext(
                    method=str(authentication.get("method", "unknown")),
                    phishing_resistant=bool(
                        authentication.get("phishing_resistant", False)
                    ),
                ),
                provenance=tuple(
                    PolicyProvenanceEdge(
                        sequence=edge.sequence,
                        from_type=edge.from_type,
                        relationship=edge.relationship_type,
                        to_type=edge.to_type,
                    )
                    for edge in entitlement.provenance_edges
                ),
            ),
        )


def load_policy_evaluations(
    session: Session, identity_id: object
) -> Iterable[PolicyEvaluation]:
    return session.scalars(
        select(PolicyEvaluation)
        .join(PolicyEvaluation.entitlement)
        .where(EffectiveEntitlement.identity_id == identity_id)
        .order_by(PolicyEvaluation.evaluated_at.desc(), PolicyEvaluation.id)
    )
