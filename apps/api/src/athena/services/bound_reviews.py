"""Authenticated exact-target review and independently recorded manual fulfillment."""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from athena.auth import ADMINISTRATOR, REVIEWER, Principal, authorize
from athena.config import Settings
from athena.models import (
    AccessGrant,
    AuditEvent,
    ConnectorCheckpoint,
    EffectiveEntitlement,
    Identity,
    PolicyEvaluation,
    ReviewCase,
    ReviewDecision,
    Reviewer,
    ReviewEvent,
    ReviewStatus,
    RiskFinding,
)
from athena.services.review_person_bindings import check_bindings, person_binding
from athena.tenant_queries import tenant_select


def digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class BoundReviewService:
    def __init__(self, session: Session, settings: Settings):
        self.session = session
        self.settings = settings

    def actor(self, principal: Principal) -> dict:
        issuer = principal.claims.get("iss")
        if issuer != self.settings.oidc_issuer or not principal.subject:
            raise ValueError("A verified issuer and subject are required")
        return {"issuer": issuer, "subject": principal.subject, "label": principal.username}

    def get(self, model, identifier):
        item = self.session.scalar(tenant_select(self.session, model, model.id == identifier))
        if item is None:
            raise ValueError("Requested evidence or principal is unavailable in this tenant")
        return item

    def register(self, identity_id: uuid.UUID, principal: Principal, reason: str) -> Reviewer:
        authorize(principal, ADMINISTRATOR)
        actor = self.actor(principal)
        identity = self.get(Identity, identity_id)
        if identity.source != self.settings.oidc_identity_source or not identity.active:
            raise ValueError(
                "Reviewer must be an active account from the authoritative OIDC source"
            )
        existing = self.session.scalar(
            tenant_select(
                self.session,
                Reviewer,
                Reviewer.issuer == actor["issuer"],
                Reviewer.subject == identity.external_id,
            )
        )
        if existing is not None:
            return existing
        reviewer = Reviewer(
            identity_id=identity.id,
            issuer=actor["issuer"],
            subject=identity.external_id,
            display_name=identity.display_name,
            active=True,
            provenance={"registered_by": actor, "reason": reason},
        )
        self.session.add(reviewer)
        self.session.flush()
        self._registry_audit(reviewer, actor, reason)
        self.session.commit()
        return reviewer

    def set_eligible(self, reviewer_id: uuid.UUID, active: bool, principal: Principal, reason: str):
        authorize(principal, ADMINISTRATOR)
        reviewer = self.get(Reviewer, reviewer_id)
        reviewer.active = active
        self._registry_audit(reviewer, self.actor(principal), reason)
        self.session.commit()
        return reviewer

    def _registry_audit(self, reviewer: Reviewer, actor: dict, reason: str):
        self.session.add(
            AuditEvent(
                actor_type="human",
                actor_id=actor["subject"],
                action="reviewer.eligibility_recorded",
                entity_type="reviewer",
                entity_id=str(reviewer.id),
                new_state={"active": reviewer.active, "actor": actor},
                reason=reason,
            )
        )

    def eligible(self, identifier: uuid.UUID) -> Reviewer:
        reviewer = self.session.scalar(
            tenant_select(
                self.session,
                Reviewer,
                Reviewer.id == identifier,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if reviewer is None:
            raise ValueError("Reviewer is unavailable in this tenant")
        account = self.get(Identity, reviewer.identity_id)
        if (
            not reviewer.active
            or not account.active
            or account.source != self.settings.oidc_identity_source
            or account.external_id != reviewer.subject
            or reviewer.issuer != self.settings.oidc_issuer
        ):
            raise ValueError("Reviewer is no longer eligible")
        return reviewer

    def target(self, entitlement: EffectiveEntitlement) -> dict:
        grant = entitlement.grant
        permission = entitlement.permission
        return {
            "identity_id": str(entitlement.identity_id),
            "entitlement_id": str(entitlement.id),
            "grant_id": str(grant.id),
            "source": grant.source,
            "grant_external_id": grant.external_id,
            "source_assignment_id": grant.source_metadata.get("source_assignment_id"),
            "scope": grant.source_metadata.get("subscription_id")
            or permission.resource.source_metadata.get("organization"),
            "resource_id": str(permission.resource_id),
            "permission_id": str(permission.id),
            "action": permission.action,
            "subject_type": grant.subject_type.value,
            "grant_identity_id": str(grant.identity_id) if grant.identity_id else None,
            "grant_group_id": str(grant.group_id) if grant.group_id else None,
            "limitations": grant.source_metadata,
        }

    def open(
        self,
        identity_id: uuid.UUID,
        finding_id: uuid.UUID | None,
        policy_id: uuid.UUID | None,
        decision: ReviewDecision,
        goal: str,
        due_days: int,
        principal: Principal,
    ) -> ReviewCase:
        if (finding_id is None) == (policy_id is None):
            raise ValueError("Select exactly one risk finding or policy evaluation")
        identity = self.get(Identity, identity_id)
        evidence = (
            self.get(RiskFinding, finding_id)
            if finding_id
            else self.get(PolicyEvaluation, policy_id)
        )
        entitlement = self.get(EffectiveEntitlement, evidence.entitlement_id)
        if entitlement.identity_id != identity.id or not entitlement.active:
            raise ValueError("Evidence must identify an active entitlement for this identity")
        observed = evidence.assessment.evaluated_at if finding_id else evidence.evaluated_at
        self._fresh(observed)
        if goal not in {"assignment_removed", "no_supported_paths", "record_decision"}:
            raise ValueError("Unsupported closure goal")
        if (decision == ReviewDecision.REVOKE) != (goal != "record_decision"):
            raise ValueError("Removal goals require a revoke proposal")
        target = self.target(entitlement)
        key = digest(
            {
                "identity": str(identity.id),
                "entitlement": str(entitlement.id),
                "decision": decision.value,
                "goal": goal,
            }
        )
        existing = self.session.scalar(
            tenant_select(
                self.session,
                ReviewCase,
                ReviewCase.target_key == key,
                ReviewCase.status.in_([ReviewStatus.OPEN, ReviewStatus.IN_REVIEW]),
            )
        )
        if existing:
            return existing
        snapshot = {
            "contract": "bound-review-v2",
            "target": target,
            "target_digest": digest(target),
            "evidence_id": str(evidence.id),
            "evidence_kind": "risk" if finding_id else "policy",
            "evidence_version": evidence.assessment.model_version
            if finding_id
            else evidence.policy_version,
            "evaluated_at": utc(observed).isoformat(),
            "opener": self.actor(principal),
            "proposed_action": decision.value,
            "closure_goal": goal,
            "person_binding": person_binding(self.session, self.settings, identity),
        }
        case = ReviewCase(
            identity_id=identity.id,
            entitlement_id=entitlement.id,
            risk_assessment_id=evidence.assessment_id if finding_id else None,
            policy_evaluation_id=policy_id,
            title=f"Review {identity.username}: {entitlement.permission.name}"[:255],
            status=ReviewStatus.OPEN,
            due_at=datetime.now(UTC) + timedelta(days=due_days),
            target_key=key,
            target_snapshot=snapshot,
            revision=1,
        )
        self.session.add(case)
        self._event(case, principal, "opened", "Exact target selected", snapshot, bump=False)
        self.session.commit()
        return case

    def _fresh(self, observed: datetime):
        age = datetime.now(UTC) - utc(observed)
        if age < timedelta(0) or age > timedelta(hours=24):
            raise ValueError("Evidence is not current; recollect and reassess before approval")

    def locked(self, identifier: uuid.UUID, revision: int) -> ReviewCase:
        case = self.session.scalar(
            tenant_select(
                self.session,
                ReviewCase,
                ReviewCase.id == identifier,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if case is None or case.revision != revision:
            raise ValueError("Review changed or is unavailable; reload before retrying")
        if not case.target_snapshot:
            raise ValueError("Legacy review is unbound; open a fresh exact-target review")
        return case

    def assign(
        self,
        identifier: uuid.UUID,
        revision: int,
        reviewer_id: uuid.UUID,
        principal: Principal,
        reason: str,
    ):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        if case.status not in {ReviewStatus.OPEN, ReviewStatus.IN_REVIEW}:
            raise ValueError("Only active reviews can be assigned")
        reviewer = self.eligible(reviewer_id)
        target_binding = person_binding(
            self.session, self.settings, self.get(Identity, case.identity_id)
        )
        if target_binding != case.target_snapshot.get("person_binding"):
            raise ValueError("Target person binding changed; open a fresh review")
        reviewer_binding = person_binding(
            self.session,
            self.settings,
            self.get(Identity, reviewer.identity_id),
        )
        check_bindings(target_binding, reviewer_binding)
        case.owner_id, case.owner = reviewer.id, reviewer.display_name
        self._event(
            case,
            principal,
            "assigned",
            reason,
            {
                "owner_id": str(reviewer.id),
                "person_bindings": {
                    "target": target_binding,
                    "reviewer": reviewer_binding,
                },
            },
            status=ReviewStatus.IN_REVIEW,
        )
        self.session.commit()
        return case

    def decide(
        self,
        identifier: uuid.UUID,
        revision: int,
        decision: ReviewDecision,
        principal: Principal,
        reason: str,
    ):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        if case.status != ReviewStatus.IN_REVIEW or case.owner_id is None:
            raise ValueError("Review must have an eligible bound owner")
        owner = self.eligible(case.owner_id)
        actor = self.actor(principal)
        if (owner.issuer, owner.subject) != (actor["issuer"], actor["subject"]):
            raise ValueError("Only the immutable assigned principal can decide")
        snapshot = case.target_snapshot
        if decision.value != snapshot["proposed_action"]:
            raise ValueError("Decision differs from the reviewed proposal; open a new review")
        entitlement = self.get(EffectiveEntitlement, case.entitlement_id)
        if not entitlement.active or digest(self.target(entitlement)) != snapshot["target_digest"]:
            raise ValueError("Reviewed target changed; fresh approval is required")
        self._fresh(datetime.fromisoformat(snapshot["evaluated_at"]))
        identity = self.get(Identity, case.identity_id)
        target_binding = person_binding(self.session, self.settings, identity)
        reviewer_binding = person_binding(
            self.session,
            self.settings,
            self.get(Identity, owner.identity_id),
        )
        assignment = self.latest(case, "assigned")
        bindings = {"target": target_binding, "reviewer": reviewer_binding}
        if (
            target_binding != snapshot.get("person_binding")
            or assignment is None
            or bindings != assignment.evidence_snapshot.get("person_bindings")
        ):
            raise ValueError(
                "Person binding changed since review or assignment; open a fresh review"
            )
        check_bindings(target_binding, reviewer_binding)
        if owner.identity_id == identity.id:
            raise ValueError("Self-review is prohibited")
        if decision != ReviewDecision.RETAIN:
            if identity.source != self.settings.oidc_identity_source:
                raise ValueError("Cross-source self-review binding is unresolved")
            opener = snapshot["opener"]
            if (actor["issuer"], actor["subject"]) == (opener["issuer"], opener["subject"]):
                raise ValueError("Approval requires a reviewer independent of the opener")
        case.resolution, case.resolved_at = decision, datetime.now(UTC)
        self._event(
            case,
            principal,
            "decided",
            reason,
            {"decision": decision.value, "person_bindings": bindings},
            status=ReviewStatus.RESOLVED,
            pending=decision != ReviewDecision.RETAIN,
        )
        self.session.commit()
        return case

    def cancel(self, identifier: uuid.UUID, revision: int, principal: Principal, reason: str):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        if case.status not in {ReviewStatus.OPEN, ReviewStatus.IN_REVIEW}:
            raise ValueError("Only active reviews can be cancelled")
        self._event(case, principal, "cancelled", reason, {}, status=ReviewStatus.CANCELLED)
        self.session.commit()
        return case

    def _event(
        self,
        case: ReviewCase,
        principal: Principal,
        action: str,
        reason: str,
        evidence: dict,
        *,
        status=None,
        pending=False,
        bump=True,
    ):
        previous = case.status
        if len(reason.strip()) < 10:
            raise ValueError("A reason of at least 10 characters is required")
        if bump:
            case.revision += 1
        case.status = status or case.status
        case.events.append(
            ReviewEvent(
                actor=principal.username,
                action=action,
                from_status=previous,
                to_status=case.status,
                decision=case.resolution if action == "decided" else None,
                reason=reason.strip(),
                evidence_snapshot={
                    **evidence,
                    "actor": self.actor(principal),
                    "revision": case.revision,
                    "target_digest": case.target_snapshot["target_digest"],
                },
                execution_status="pending" if pending else "not_applicable",
            )
        )

    def latest(self, case: ReviewCase, action: str):
        matches = [event for event in case.events if event.action == action]
        return max(
            matches, key=lambda item: item.evidence_snapshot.get("revision", 0), default=None
        )

    def fulfill(
        self,
        identifier: uuid.UUID,
        revision: int,
        operator_id: uuid.UUID | None,
        principal: Principal,
        reason: str,
        complete: bool,
        due_days: int,
    ):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        if case.status != ReviewStatus.RESOLVED or case.resolution != ReviewDecision.REVOKE:
            raise ValueError("Manual removal requires a resolved revoke approval")
        actor = self.actor(principal)
        if complete:
            assignment = self.latest(case, "fulfillment_assigned")
            completion = self.latest(case, "operator_completed")
            if assignment is None or (
                completion is not None
                and completion.evidence_snapshot["revision"]
                > assignment.evidence_snapshot["revision"]
            ):
                raise ValueError("No pending manual fulfillment assignment")
            operator = self.eligible(uuid.UUID(assignment.evidence_snapshot["operator_id"]))
            if (operator.issuer, operator.subject) != (actor["issuer"], actor["subject"]):
                raise ValueError("Only the assigned operator can record completion")
            self._event(
                case,
                principal,
                "operator_completed",
                reason,
                {
                    "completed_at": datetime.now(UTC).isoformat(),
                    "operator_id": str(operator.id),
                },
                pending=True,
            )
        else:
            completion = self.latest(case, "operator_completed")
            verification = self.latest(case, "verification_recorded")
            if completion and (
                verification is None
                or verification.evidence_snapshot["revision"]
                < completion.evidence_snapshot["revision"]
                or verification.evidence_snapshot["outcome"] == "verified"
            ):
                raise ValueError("Verify completion before assigning further correction work")
            if operator_id is None:
                raise ValueError("Select a fulfillment operator")
            operator = self.eligible(operator_id)
            if operator.id == case.owner_id or operator.identity_id == case.identity_id:
                raise ValueError("Fulfillment must be independent of approver and target")
            self._event(
                case,
                principal,
                "fulfillment_assigned",
                reason,
                {
                    "operator_id": str(operator.id),
                    "due_at": (datetime.now(UTC) + timedelta(days=due_days)).isoformat(),
                },
                pending=True,
            )
        self.session.commit()
        return case

    def request_verification(self, identifier: uuid.UUID, revision: int, principal: Principal):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        completion = self.latest(case, "operator_completed")
        assignment = self.latest(case, "fulfillment_assigned")
        if completion is None or (
            assignment
            and assignment.evidence_snapshot["revision"] > completion.evidence_snapshot["revision"]
        ):
            raise ValueError("Record operator completion before requesting verification")
        self._event(
            case,
            principal,
            "verification_requested",
            "Requested fresh read-only verification",
            {"completion_id": str(completion.id)},
            pending=True,
        )
        self.session.commit()
        return case

    def verify(self, identifier: uuid.UUID, revision: int, principal: Principal):
        authorize(principal, REVIEWER)
        case = self.locked(identifier, revision)
        completion = self.latest(case, "operator_completed")
        assignment = self.latest(case, "fulfillment_assigned")
        if completion is None or (
            assignment
            and assignment.evidence_snapshot["revision"] > completion.evidence_snapshot["revision"]
        ):
            raise ValueError("Record operator completion before verification")
        target = case.target_snapshot["target"]
        result = {
            "outcome": "insufficient_coverage",
            "closure_goal": case.target_snapshot["closure_goal"],
        }
        if target["source"] == "azure_rbac" and target["source_assignment_id"] and target["scope"]:
            checkpoint = self.session.scalar(
                tenant_select(
                    self.session,
                    ConnectorCheckpoint,
                    ConnectorCheckpoint.connector == "azure_rbac",
                    ConnectorCheckpoint.scope == target["scope"],
                )
            )
            completed_at = datetime.fromisoformat(completion.evidence_snapshot["completed_at"])
            if checkpoint is None or utc(checkpoint.observed_at) <= completed_at:
                result["outcome"] = "collection_required"
            else:
                self._fresh(checkpoint.observed_at)
                entitlement = self.get(EffectiveEntitlement, case.entitlement_id)
                if digest(self.target(entitlement)) != case.target_snapshot["target_digest"]:
                    raise ValueError("Verification target changed")
                result.update(
                    {
                        "checkpoint_id": str(checkpoint.id),
                        "fingerprint": checkpoint.fingerprint,
                        "observed_at": utc(checkpoint.observed_at).isoformat(),
                    }
                )
                assignment_present = (
                    self.session.scalar(
                        tenant_select(
                            self.session,
                            AccessGrant,
                            AccessGrant.source == "azure_rbac",
                            AccessGrant.source_metadata["source_assignment_id"].as_string()
                            == target["source_assignment_id"],
                            AccessGrant.source_metadata["subscription_id"].as_string()
                            == target["scope"],
                            AccessGrant.revoked_at.is_(None),
                        ).limit(1)
                    )
                    is not None
                )
                path_present = (
                    self.session.scalar(
                        tenant_select(
                            self.session,
                            EffectiveEntitlement,
                            EffectiveEntitlement.identity_id == case.identity_id,
                            EffectiveEntitlement.permission_id == entitlement.permission_id,
                            EffectiveEntitlement.active.is_(True),
                        ).limit(1)
                    )
                    is not None
                )
                if assignment_present or entitlement.active or entitlement.grant.revoked_at is None:
                    result["outcome"] = "still_present"
                elif case.target_snapshot["closure_goal"] == "assignment_removed":
                    result["outcome"] = "verified"
                elif path_present:
                    result["outcome"] = "still_present"
        self._event(
            case, principal, "verification_recorded", "Read-only evidence verification", result
        )
        self.session.commit()
        return case

    def report(self, identifier: uuid.UUID) -> dict:
        case = self.get(ReviewCase, identifier)
        packet = {
            "case_id": str(case.id),
            "revision": case.revision,
            "target": case.target_snapshot,
            "decision": case.resolution.value if case.resolution else None,
            "events": [
                {
                    "id": str(event.id),
                    "at": utc(event.occurred_at).isoformat(),
                    "action": event.action,
                    "reason": event.reason,
                    "evidence": event.evidence_snapshot,
                }
                for event in case.events
            ],
        }
        return {"packet": packet, "digest": digest(packet)}
