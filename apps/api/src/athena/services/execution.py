import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AccessGrant,
    EffectiveEntitlement,
    ExecutionStatus,
    RemediationExecution,
    RemediationExecutionEvent,
    ReviewCase,
    ReviewDecision,
    ReviewStatus,
)
from athena.services.provenance import ProvenanceService


class ExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionTarget:
    source: str
    grant_external_id: str
    identity_external_id: str
    permission_action: str
    resource_external_id: str


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    evidence: dict


class RemediationAdapter(Protocol):
    source: str

    def revoke(self, target: ExecutionTarget, idempotency_key: str) -> dict: ...

    def verify_revoked(self, target: ExecutionTarget) -> VerificationResult: ...


class ExecutionService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def request(
        self, case: ReviewCase, requested_by: str, idempotency_key: str
    ) -> RemediationExecution:
        key = idempotency_key.strip()
        if not key:
            raise ExecutionError("An idempotency key is required")
        existing = self.session.scalar(
            select(RemediationExecution).where(
                (RemediationExecution.case_id == case.id)
                | (RemediationExecution.idempotency_key == key)
            )
        )
        if existing is not None:
            if existing.case_id != case.id or existing.idempotency_key != key:
                raise ExecutionError("Execution request conflicts with existing idempotency state")
            return existing
        if case.status != ReviewStatus.RESOLVED or case.resolution != ReviewDecision.REVOKE:
            raise ExecutionError("Only a resolved revoke decision can create an execution")
        if case.entitlement_id is None:
            raise ExecutionError("The review does not identify an entitlement to revoke")
        entitlement = self.session.get(EffectiveEntitlement, case.entitlement_id)
        if entitlement is None or not entitlement.active:
            raise ExecutionError("The reviewed entitlement is not active")
        grant = self.session.get(AccessGrant, entitlement.grant_id)
        if grant is None or grant.revoked_at is not None:
            raise ExecutionError("The reviewed grant is already revoked or unavailable")
        target = self._target(entitlement, grant)
        execution = RemediationExecution(
            case_id=case.id,
            entitlement_id=entitlement.id,
            source=grant.source,
            action="revoke",
            target_external_id=grant.external_id,
            idempotency_key=key,
            requested_by=requested_by,
            status=ExecutionStatus.PENDING,
            before_evidence={
                "target": target.__dict__,
                "entitlement_active": entitlement.active,
                "grant_revoked_at": None,
                "review_decision": case.resolution.value,
                "review_event_id": str(case.events[-1].id) if case.events else None,
            },
        )
        execution.events.append(
            RemediationExecutionEvent(
                actor=requested_by,
                action="requested",
                from_status=None,
                to_status=ExecutionStatus.PENDING,
                evidence={"idempotency_key": key, "case_id": str(case.id)},
            )
        )
        self.session.add(execution)
        self.session.commit()
        return execution

    def run(
        self, execution: RemediationExecution, actor: str, adapter: RemediationAdapter
    ) -> RemediationExecution:
        if execution.status == ExecutionStatus.SUCCEEDED:
            return execution
        if execution.status == ExecutionStatus.RUNNING:
            raise ExecutionError("Execution is already running")
        if adapter.source != execution.source:
            raise ExecutionError("Adapter source does not match the execution source")
        entitlement = self.session.get(EffectiveEntitlement, execution.entitlement_id)
        if entitlement is None:
            raise ExecutionError("Execution entitlement is unavailable")
        grant = self.session.get(AccessGrant, entitlement.grant_id)
        if grant is None:
            raise ExecutionError("Execution grant is unavailable")
        target = self._target(entitlement, grant)
        previous = execution.status
        execution.status = ExecutionStatus.RUNNING
        execution.attempt_count += 1
        execution.started_at = datetime.now(UTC)
        execution.completed_at = None
        execution.error = None
        execution.events.append(
            RemediationExecutionEvent(
                actor=actor,
                action="started",
                from_status=previous,
                to_status=ExecutionStatus.RUNNING,
                evidence={"attempt": execution.attempt_count},
            )
        )
        self.session.commit()
        try:
            receipt = adapter.revoke(target, execution.idempotency_key)
            verification = adapter.verify_revoked(target)
        except Exception as error:
            message = (
                str(error)
                if isinstance(error, ExecutionError)
                else f"{type(error).__name__}: remediation adapter failed"
            )
            self._finish_failure(execution, actor, ExecutionStatus.FAILED, message)
            return execution
        execution.adapter_receipt = receipt
        execution.after_evidence = verification.evidence
        if not verification.verified:
            self._finish_failure(
                execution,
                actor,
                ExecutionStatus.VERIFICATION_FAILED,
                "Upstream revocation could not be verified",
            )
            return execution
        grant.revoked_at = datetime.now(UTC)
        self.session.flush()
        ProvenanceService(self.session).materialize_identity(entitlement.identity)
        execution.status = ExecutionStatus.SUCCEEDED
        execution.completed_at = datetime.now(UTC)
        execution.events.append(
            RemediationExecutionEvent(
                actor=actor,
                action="verified",
                from_status=ExecutionStatus.RUNNING,
                to_status=ExecutionStatus.SUCCEEDED,
                evidence=verification.evidence,
            )
        )
        self.session.commit()
        return execution

    def _finish_failure(
        self,
        execution: RemediationExecution,
        actor: str,
        status: ExecutionStatus,
        error: str,
    ) -> None:
        sanitized = error.strip()[:2000] or "Remediation adapter failed"
        execution.status = status
        execution.completed_at = datetime.now(UTC)
        execution.error = sanitized
        execution.events.append(
            RemediationExecutionEvent(
                actor=actor,
                action="failed",
                from_status=ExecutionStatus.RUNNING,
                to_status=status,
                evidence={"attempt": execution.attempt_count},
                error=sanitized,
            )
        )
        self.session.commit()

    @staticmethod
    def _target(entitlement: EffectiveEntitlement, grant: AccessGrant) -> ExecutionTarget:
        identity = entitlement.identity
        permission = entitlement.permission
        return ExecutionTarget(
            source=grant.source,
            grant_external_id=grant.external_id,
            identity_external_id=identity.external_id,
            permission_action=permission.action,
            resource_external_id=permission.resource.external_id,
        )


def load_execution(session: Session, execution_id: uuid.UUID) -> RemediationExecution | None:
    return session.scalar(
        select(RemediationExecution)
        .options(selectinload(RemediationExecution.events))
        .where(RemediationExecution.id == execution_id)
    )


def load_executions(session: Session) -> list[RemediationExecution]:
    return list(
        session.scalars(
            select(RemediationExecution)
            .options(selectinload(RemediationExecution.events))
            .order_by(RemediationExecution.created_at.desc())
        )
    )
