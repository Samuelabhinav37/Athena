"""Recover pending read-only verification from durable completion events."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError

from athena.auth import REVIEWER, Principal
from athena.models import MonitoringRun, MonitoringStatus, ReviewCase, ReviewDecision, ReviewStatus
from athena.services.bound_reviews import utc
from athena.services.review_collection import ReviewCollectionService
from athena.tenant_queries import tenant_select


class _WorkerCollection(ReviewCollectionService):
    """Internal service attribution; never constructed by JWT authentication."""

    principal = Principal("review-recollection", "athena-review-worker", frozenset({REVIEWER}), {})

    def actor(self, principal):
        if principal is self.principal:
            return {
                "issuer": "urn:athena:internal-worker",
                "subject": principal.subject,
                "label": principal.username,
                "kind": "service",
            }
        return super().actor(principal)


class ReviewRetryWorker:
    def __init__(self, session, settings, *, clock=None):
        self.session = session
        self.service = _WorkerCollection(session, settings)
        self.clock = clock or (lambda: datetime.now(UTC))

    def ready(self, case):
        return self.collection_status(case)["state"] == "queued"

    def collection_status(self, case):
        status = {
            "state": "not_requested",
            "attempts": 0,
            "max_attempts": 5,
            "next_retry_at": None,
            "outcome": None,
        }
        if (
            case.status != ReviewStatus.RESOLVED
            or case.resolution != ReviewDecision.REVOKE
            or not case.target_key
        ):
            return status
        completion = self.service.latest(case, "operator_completed")
        if completion is None:
            return status
        request = self.service.latest(case, "verification_requested")
        work = (
            request
            if request
            and request.evidence_snapshot["revision"] > completion.evidence_snapshot["revision"]
            else completion
        )
        revision = work.evidence_snapshot["revision"]
        assignment = self.service.latest(case, "fulfillment_assigned")
        verification = self.service.latest(case, "verification_recorded")
        if assignment and assignment.evidence_snapshot["revision"] > revision:
            return status
        prefix = f"review-collection:{work.id}:"
        runs = list(
            self.session.scalars(
                tenant_select(
                    self.session,
                    MonitoringRun,
                    MonitoringRun.schedule_key.startswith(prefix),
                )
            )
        )
        status["attempts"] = sum(run.attempt_count for run in runs)
        if (
            verification
            and verification.evidence_snapshot["revision"] > revision
            and verification.evidence_snapshot["outcome"] != "collection_required"
        ):
            status.update(state="completed", outcome=verification.evidence_snapshot["outcome"])
            return status
        now = self.clock()
        if any(
            run.status == MonitoringStatus.RUNNING
            and run.lease_expires_at
            and utc(run.lease_expires_at) > now
            for run in runs
        ):
            status["state"] = "running"
            return status
        attempts = sum(run.attempt_count for run in runs)
        # This limit spans hourly schedule keys and process restarts. Explicit
        # human retry remains available after the automatic budget is exhausted.
        if attempts >= 5:
            status["state"] = "exhausted"
            return status
        last = max(
            (
                utc(run.completed_at or run.started_at)
                for run in runs
                if run.completed_at or run.started_at
            ),
            default=None,
        )
        delay = min(3600, 60 * 2 ** max(0, attempts - 1))
        next_retry = last + timedelta(seconds=delay) if last else now
        status["state"] = "queued" if now >= next_retry else "retry_wait"
        status["next_retry_at"] = next_retry.isoformat()
        return status

    def run_once(self, *, limit=100):
        if not 1 <= limit <= 1000:
            raise ValueError("Worker limit must be between 1 and 1000")
        counts = {
            "attempted": 0,
            "verification_recorded": 0,
            "failed": 0,
            "deferred": 0,
            "exhausted": 0,
            "scan_complete": False,
        }
        cursor = None
        while counts["attempted"] < limit:
            statement = (
                tenant_select(
                    self.session,
                    ReviewCase,
                    ReviewCase.status == ReviewStatus.RESOLVED,
                    ReviewCase.resolution == ReviewDecision.REVOKE,
                    ReviewCase.target_key.is_not(None),
                )
                .order_by(ReviewCase.id)
                .limit(100)
            )
            if cursor is not None:
                statement = statement.where(ReviewCase.id > cursor)
            cases = list(self.session.scalars(statement))
            if not cases:
                counts["scan_complete"] = True
                break
            for case in cases:
                cursor = case.id
                state = self.collection_status(case)["state"]
                if state != "queued":
                    if state == "exhausted":
                        counts["exhausted"] += 1
                    counts["deferred"] += 1
                    continue
                counts["attempted"] += 1
                try:
                    self.service.collect_and_verify(
                        case.id,
                        case.revision,
                        self.service.principal,
                    )
                except (ValueError, SQLAlchemyError):
                    self.session.rollback()
                    counts["failed"] += 1
                    if self.collection_status(case)["state"] == "exhausted":
                        counts["exhausted"] += 1
                else:
                    counts["verification_recorded"] += 1
                if counts["attempted"] >= limit:
                    break
            # End any read transaction before advancing the keyset page.
            self.session.rollback()
        return counts
