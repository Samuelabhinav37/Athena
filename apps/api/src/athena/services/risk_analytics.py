import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AccessObservation,
    EffectiveEntitlement,
    Identity,
    PolicyDecision,
    PolicyEvaluation,
    RiskAssessment,
    RiskFinding,
    RiskFindingType,
    RiskLevel,
    RoleTransition,
    Sensitivity,
)

MODEL_VERSION = "access-decay-v1"
SENSITIVITY_FACTORS = {
    Sensitivity.LOW: 0.1,
    Sensitivity.MODERATE: 0.4,
    Sensitivity.HIGH: 0.7,
    Sensitivity.CRITICAL: 1.0,
}
WEIGHTS = {
    "retained_access": 20.0,
    "privilege": 15.0,
    "sensitivity": 15.0,
    "time_since_use": 15.0,
    "peer_deviation": 15.0,
    "policy_risk": 15.0,
    "authentication_risk": 5.0,
}


@dataclass(frozen=True)
class RiskAssessmentResult:
    assessment_id: uuid.UUID
    score: float
    level: RiskLevel
    findings: int
    model_version: str


class RiskAnalyticsService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def assess(self, identity: Identity) -> RiskAssessmentResult:
        now = datetime.now(UTC)
        entitlements = list(
            self.session.scalars(
                select(EffectiveEntitlement)
                .options(selectinload(EffectiveEntitlement.provenance_edges))
                .where(
                    EffectiveEntitlement.identity_id == identity.id,
                    EffectiveEntitlement.active.is_(True),
                )
            ).unique()
        )
        peers = list(
            self.session.scalars(
                select(Identity).where(
                    Identity.id != identity.id,
                    Identity.active.is_(True),
                    Identity.department == identity.department,
                )
            )
        )
        peer_ids = [peer.id for peer in peers]
        peer_permissions = set()
        if peer_ids:
            peer_permissions = set(
                self.session.scalars(
                    select(EffectiveEntitlement.permission_id).where(
                        EffectiveEntitlement.identity_id.in_(peer_ids),
                        EffectiveEntitlement.active.is_(True),
                    )
                )
            )
        transition = self.session.scalar(
            select(RoleTransition)
            .where(RoleTransition.identity_id == identity.id)
            .order_by(RoleTransition.effective_at.desc())
        )

        assessment = RiskAssessment(
            identity=identity,
            model_version=MODEL_VERSION,
            score=0,
            level=RiskLevel.LOW,
            peer_definition={
                "department": identity.department,
                "roles": sorted(role.name for role in identity.roles),
                "peer_count": len(peers),
                "peers": sorted(peer.username for peer in peers),
            },
            summary={},
        )
        self.session.add(assessment)
        finding_scores = []
        for entitlement in entitlements:
            factors = self._factors(
                identity,
                entitlement,
                peer_permissions,
                transition,
                now,
            )
            score = round(
                sum(WEIGHTS[name] * value for name, value in factors.items()), 2
            )
            finding_scores.append(score)
            finding_type = self._finding_type(factors)
            assessment.findings.append(
                RiskFinding(
                    entitlement=entitlement,
                    finding_type=finding_type,
                    score=score,
                    factors={
                        name: {"value": value, "weight": WEIGHTS[name]}
                        for name, value in factors.items()
                    },
                    explanation=self._explanation(entitlement, factors, score),
                )
            )

        overall_score = max(finding_scores, default=0.0)
        assessment.score = overall_score
        assessment.level = self._level(overall_score)
        assessment.summary = {
            "active_entitlements": len(entitlements),
            "retained_entitlements": sum(
                finding.factors["retained_access"]["value"] == 1.0
                for finding in assessment.findings
            ),
            "peer_deviations": sum(
                finding.factors["peer_deviation"]["value"] == 1.0
                for finding in assessment.findings
            ),
            "high_risk_entitlements": sum(score >= 60 for score in finding_scores),
        }
        self.session.commit()
        return RiskAssessmentResult(
            assessment_id=assessment.id,
            score=assessment.score,
            level=assessment.level,
            findings=len(assessment.findings),
            model_version=assessment.model_version,
        )

    def _factors(
        self,
        identity: Identity,
        entitlement: EffectiveEntitlement,
        peer_permissions: set[uuid.UUID],
        transition: RoleTransition | None,
        now: datetime,
    ) -> dict[str, float]:
        permission = entitlement.permission
        observation = self.session.scalar(
            select(AccessObservation)
            .where(AccessObservation.entitlement_id == entitlement.id)
            .order_by(AccessObservation.observed_at.desc())
        )
        if observation is None or observation.last_used_at is None:
            time_factor = 1.0
        else:
            last_used = observation.last_used_at
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=UTC)
            time_factor = min(max((now - last_used).days / 90, 0.0), 1.0)
        latest_policy = self.session.scalar(
            select(PolicyEvaluation)
            .where(PolicyEvaluation.entitlement_id == entitlement.id)
            .order_by(PolicyEvaluation.evaluated_at.desc())
        )
        policy_factor = 0.0
        if latest_policy is not None:
            policy_factor = {
                PolicyDecision.PASS: 0.0,
                PolicyDecision.FAIL: 1.0,
                PolicyDecision.ERROR: 0.75,
            }[latest_policy.decision]
        peer_factor = 0.0 if permission.id in peer_permissions else 1.0
        retained = bool(
            transition is not None
            and entitlement.grant.granted_at <= transition.effective_at
            and peer_factor == 1.0
        )
        authentication = identity.source_metadata.get("authentication", {})
        phishing_resistant = (
            isinstance(authentication, dict)
            and authentication.get("phishing_resistant") is True
        )
        authentication_factor = (
            0.0 if phishing_resistant else (1.0 if permission.privileged else 0.2)
        )
        return {
            "retained_access": 1.0 if retained else 0.0,
            "privilege": 1.0 if permission.privileged else 0.3,
            "sensitivity": SENSITIVITY_FACTORS[permission.resource.sensitivity],
            "time_since_use": round(time_factor, 4),
            "peer_deviation": peer_factor,
            "policy_risk": policy_factor,
            "authentication_risk": authentication_factor,
        }

    @staticmethod
    def _finding_type(factors: dict[str, float]) -> RiskFindingType:
        if factors["retained_access"] == 1.0:
            return RiskFindingType.RETAINED_ACCESS
        if factors["policy_risk"] > 0:
            return RiskFindingType.POLICY_VIOLATION
        if factors["time_since_use"] >= 1.0:
            return RiskFindingType.STALE_ACCESS
        return RiskFindingType.PEER_DEVIATION

    @staticmethod
    def _level(score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _explanation(
        entitlement: EffectiveEntitlement, factors: dict[str, float], score: float
    ) -> str:
        contributors = [name for name, value in factors.items() if value >= 0.75]
        return (
            f"{entitlement.permission.name} scored {score:.2f}/100; "
            f"primary factors: {', '.join(contributors) or 'none'}."
        )


def load_risk_assessments(session: Session, identity_id: uuid.UUID) -> list[RiskAssessment]:
    return list(
        session.scalars(
            select(RiskAssessment)
            .options(selectinload(RiskAssessment.findings))
            .where(RiskAssessment.identity_id == identity_id)
            .order_by(RiskAssessment.evaluated_at.desc(), RiskAssessment.id)
        ).unique()
    )
