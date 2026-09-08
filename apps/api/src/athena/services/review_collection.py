"""Read-only recollection for a durable manual-completion record."""

from datetime import UTC, datetime, timedelta

from athena.auth import REVIEWER, authorize
from athena.collectors.azure import AzureCollector
from athena.models import MonitoringRun, MonitoringStatus
from athena.services.azure_sync import AzureSyncService
from athena.services.bound_reviews import BoundReviewService, utc
from athena.services.connector_scopes import ConnectorScopeRegistry
from athena.services.monitoring import MonitoringError, MonitoringService
from athena.tenant_queries import tenant_select


class ReviewCollectionService(BoundReviewService):
    def collect_and_verify(self, identifier, revision, principal):
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
        if target["source"] != "azure_rbac":
            return self.verify(identifier, revision, principal)
        completion_id = completion.id
        request = self.latest(case, "verification_requested")
        work_id = (
            request.id
            if request
            and request.evidence_snapshot["revision"] > completion.evidence_snapshot["revision"]
            else completion_id
        )
        # Persisted schedule keys make interrupted collection retryable. A later
        # verification request has a new revision and may gather newer evidence.
        # An old successful collection must not strand a request whose subsequent
        # verification crashed and is retried after its evidence has expired.
        hour = datetime.now(UTC).strftime("%Y%m%d%H")
        prefix = f"review-collection:{work_id}:{revision}:"
        key = f"{prefix}{hour}"
        previous = self.session.scalar(
            tenant_select(
                self.session,
                MonitoringRun,
                MonitoringRun.schedule_key.startswith(prefix),
            )
            .order_by(MonitoringRun.started_at.desc())
            .limit(1)
        )
        if previous is not None and (
            previous.status != MonitoringStatus.COMPLETED
            or (
                previous.completed_at
                and utc(previous.completed_at) > datetime.now(UTC) - timedelta(hours=1)
            )
        ):
            key = previous.schedule_key
        self.session.commit()

        def collect():
            try:
                settings = self.settings
                if not settings.azure_enabled or target["scope"] != settings.azure_subscription_id:
                    raise ValueError("Azure scope is not configured")
                registry = ConnectorScopeRegistry(self.session)
                scope = f"{settings.azure_tenant_id}/{settings.azure_subscription_id}"
                registry.require_approved("azure", scope)
                with AzureCollector(settings) as collector:
                    snapshot = collector.collect()
                if (snapshot.tenant_id, snapshot.subscription_id) != (
                    settings.azure_tenant_id,
                    target["scope"],
                ):
                    raise ValueError("Collected scope does not match the review")
                # Recheck approval after the network operation, before ingestion.
                registry.require_approved("azure", scope)
                AzureSyncService(self.session).sync(snapshot)
                return {"completion_id": str(completion_id), "scope": target["scope"]}
            except Exception:
                # Provider responses and credential-bearing exceptions must not
                # reach monitoring evidence or the API response.
                raise ValueError("Approved read-only Azure recollection failed") from None

        try:
            MonitoringService(self.session).run(key, principal.username, [("recollect", collect)])
        except MonitoringError:
            raise ValueError(
                "Completion remains saved. Recollection failed or is already running; "
                "reload the case and retry verification."
            ) from None
        self.session.expire_all()
        # Concurrent assignment or verification invalidates this request; never
        # apply the collected result to a different completion revision.
        return self.verify(identifier, revision, principal)
