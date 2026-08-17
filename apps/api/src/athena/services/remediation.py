import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AnomalyResult,
    Identity,
    ReviewCase,
    ReviewDecision,
    ReviewEvent,
    ReviewStatus,
    RiskAssessment,
)


@dataclass(frozen=True)
class CaseOutcome:
    case_id: uuid.UUID
    status: ReviewStatus
    resolution: ReviewDecision | None


class RemediationService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def open_for_latest_evidence(
        self, identity: Identity, actor: str, owner: str | None = None, due_days: int = 7
    ) -> CaseOutcome:
        if due_days < 1 or due_days > 90:
            raise ValueError("due_days must be between 1 and 90")
        risk = self.session.scalar(
            select(RiskAssessment)
            .where(RiskAssessment.identity_id == identity.id)
            .order_by(RiskAssessment.evaluated_at.desc())
        )
        anomaly = self.session.scalar(
            select(AnomalyResult)
            .where(AnomalyResult.identity_id == identity.id)
            .order_by(AnomalyResult.id.desc())
        )
        if risk is None and anomaly is None:
            raise ValueError("Risk or anomaly evidence is required to open a review")
        existing = self.session.scalar(
            select(ReviewCase).where(
                ReviewCase.identity_id == identity.id,
                ReviewCase.status.in_([ReviewStatus.OPEN, ReviewStatus.IN_REVIEW]),
            )
        )
        if existing is not None:
            return CaseOutcome(existing.id, existing.status, existing.resolution)
        now = datetime.now(UTC)
        entitlement_id = None
        if risk is not None and risk.findings:
            entitlement_id = max(risk.findings, key=lambda finding: finding.score).entitlement_id
        case = ReviewCase(
            identity_id=identity.id,
            entitlement_id=entitlement_id,
            risk_assessment_id=risk.id if risk else None,
            anomaly_result_id=anomaly.id if anomaly else None,
            title=f"Review unusual access for {identity.username}",
            status=ReviewStatus.OPEN,
            owner=owner,
            due_at=now + timedelta(days=due_days),
        )
        case.events.append(
            ReviewEvent(
                actor=actor,
                action="opened",
                from_status=None,
                to_status=ReviewStatus.OPEN,
                reason="Risk or anomaly evidence requires human review",
                evidence_snapshot=self._snapshot(risk, anomaly),
                execution_status="not_applicable",
            )
        )
        self.session.add(case)
        self.session.commit()
        return CaseOutcome(case.id, case.status, case.resolution)

    def assign(self, case: ReviewCase, owner: str, actor: str, reason: str) -> CaseOutcome:
        if case.status not in (ReviewStatus.OPEN, ReviewStatus.IN_REVIEW):
            raise ValueError("Only active cases can be assigned")
        previous = case.status
        case.owner = owner
        case.status = ReviewStatus.IN_REVIEW
        case.events.append(
            ReviewEvent(
                actor=actor,
                action="assigned",
                from_status=previous,
                to_status=ReviewStatus.IN_REVIEW,
                reason=reason,
                evidence_snapshot={"owner": owner},
                execution_status="not_applicable",
            )
        )
        self.session.commit()
        return CaseOutcome(case.id, case.status, case.resolution)

    def decide(
        self, case: ReviewCase, decision: ReviewDecision, actor: str, reason: str
    ) -> CaseOutcome:
        if case.status != ReviewStatus.IN_REVIEW or not case.owner:
            raise ValueError("A case must be assigned and in review before a decision")
        if actor != case.owner:
            raise ValueError("Only the assigned owner can decide a review")
        if len(reason.strip()) < 10:
            raise ValueError("A decision reason must contain at least 10 characters")
        previous = case.status
        case.status = ReviewStatus.RESOLVED
        case.resolution = decision
        case.resolved_at = datetime.now(UTC)
        case.events.append(
            ReviewEvent(
                actor=actor,
                action="decided",
                from_status=previous,
                to_status=ReviewStatus.RESOLVED,
                decision=decision,
                reason=reason.strip(),
                evidence_snapshot={"human_approved": True, "decision": decision.value},
                execution_status="pending"
                if decision in (ReviewDecision.REVOKE, ReviewDecision.EXTEND)
                else "not_required",
            )
        )
        self.session.commit()
        return CaseOutcome(case.id, case.status, case.resolution)

    @staticmethod
    def _snapshot(risk: RiskAssessment | None, anomaly: AnomalyResult | None) -> dict:
        return {
            "risk": None
            if risk is None
            else {
                "id": str(risk.id),
                "score": risk.score,
                "level": risk.level.value,
                "model_version": risk.model_version,
            },
            "anomaly": None
            if anomaly is None
            else {
                "id": str(anomaly.id),
                "is_anomaly": anomaly.is_anomaly,
                "decision_score": anomaly.decision_score,
                "model_version": anomaly.run.model_version,
            },
        }


def load_case(session: Session, case_id: uuid.UUID) -> ReviewCase | None:
    return session.scalar(
        select(ReviewCase).options(selectinload(ReviewCase.events)).where(ReviewCase.id == case_id)
    )


def load_cases(session: Session) -> list[ReviewCase]:
    return list(
        session.scalars(
            select(ReviewCase)
            .options(selectinload(ReviewCase.events))
            .order_by(ReviewCase.created_at.desc())
        )
    )
