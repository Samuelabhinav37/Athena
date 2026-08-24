import argparse
import json
import sys
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

from athena.collectors.azure import AzureCollectionError, AzureCollector
from athena.collectors.github import GitHubCollectionError, GitHubCollector
from athena.collectors.keycloak import KeycloakCollectionError, KeycloakCollector
from athena.config import get_settings
from athena.database import get_administrative_session_factory, get_session_factory
from athena.models import Identity, ReviewDecision
from athena.policy.opa import OpaAuthorizationAdapter, OpaClient, OpaEvaluationError
from athena.repositories import IdentityRepository
from athena.services.attack_paths import AttackPathError, Neo4jAttackPathAdapter, build_projection
from athena.services.azure_sync import AzureSyncService
from athena.services.connector_admin import (
    ConnectorAdministration,
    ConnectorAdministrationError,
    ConnectorScopeChangePlan,
)
from athena.services.connector_scopes import ConnectorScopeError, ConnectorScopeRegistry
from athena.services.demo_scenario import DemoScenarioError, DemoScenarioService
from athena.services.drift_scenario import DriftScenarioService
from athena.services.github_sync import GitHubSyncService
from athena.services.identity_sync import IdentitySyncService
from athena.services.monitoring import MonitoringError, MonitoringService
from athena.services.peer_anomaly import PeerAnomalyService
from athena.services.policy_evaluation import PolicyEvaluationService
from athena.services.provenance import ProvenanceService
from athena.services.remediation import RemediationService, load_case
from athena.services.risk_analytics import RiskAnalyticsService
from athena.services.security_gate import SecurityGateError, SecurityGateService
from athena.services.tenant_backfill import (
    build_bootstrap_backfill_plan,
    execute_bootstrap_backfill,
    load_bootstrap_approval,
)
from athena.services.tenant_constraints import build_tenant_constraint_plan
from athena.services.tenant_integrity import TenantIntegrityError, inspect_tenant_integrity
from athena.services.tenant_inventory import TenantInventoryError, capture_tenant_inventory
from athena.services.tenant_rls import build_tenant_rls_plan
from athena.tenant_transition import TenantTransitionError


def sync_keycloak(tenant_id: str) -> int:
    try:
        settings = get_settings()
        with get_session_factory(tenant_id)() as session:
            ConnectorScopeRegistry(session).require_approved(
                "keycloak", settings.keycloak_realm
            )
            with KeycloakCollector(settings) as collector:
                records = collector.collect()
            result = IdentitySyncService(session).sync(records)
    except (ConnectorScopeError, KeycloakCollectionError, SQLAlchemyError) as error:
        print(f"Keycloak synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def sync_github(tenant_id: str) -> int:
    try:
        settings = get_settings()
        with get_session_factory(tenant_id)() as session:
            ConnectorScopeRegistry(session).require_approved("github", settings.github_org)
            service = GitHubSyncService(session)
            checkpoint = service.checkpoint(settings.github_org)
            cache = checkpoint.endpoint_cache if checkpoint else None
            with GitHubCollector(settings) as collector:
                snapshot = collector.collect(cache)
            result = service.sync(snapshot)
    except (ConnectorScopeError, GitHubCollectionError, SQLAlchemyError, ValueError) as error:
        print(f"GitHub synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def sync_azure(tenant_id: str) -> int:
    try:
        settings = get_settings()
        with get_session_factory(tenant_id)() as session:
            ConnectorScopeRegistry(session).require_approved(
                "azure",
                f"{settings.azure_tenant_id}/{settings.azure_subscription_id}",
            )
            with AzureCollector(settings) as collector:
                snapshot = collector.collect()
            result = AzureSyncService(session).sync(snapshot)
    except (ConnectorScopeError, AzureCollectionError, SQLAlchemyError, ValueError) as error:
        print(f"Azure synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def seed_provenance_demo(tenant_id: str) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            result = DemoScenarioService(session).seed()
    except (DemoScenarioError, SQLAlchemyError, ValueError) as error:
        print(f"Provenance demo seed failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def project_attack_graph(tenant_id: str) -> int:
    settings = get_settings()
    try:
        with get_session_factory(tenant_id)() as session:
            projection = build_projection(session)
        with Neo4jAttackPathAdapter(settings) as adapter:
            result = adapter.project(projection)
    except (AttackPathError, SQLAlchemyError, ValueError) as error:
        print(f"Attack graph projection failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def evaluate_policies(tenant_id: str, username: str) -> int:
    settings = get_settings()
    try:
        with get_session_factory(tenant_id)() as session:
            identity = IdentityRepository(session).get_by_username(username)
            if identity is None:
                print(
                    f"Policy evaluation failed: identity {username} was not found",
                    file=sys.stderr,
                )
                return 1
            with OpaClient(settings.opa_url) as opa_client:
                result = PolicyEvaluationService(
                    session, OpaAuthorizationAdapter(opa_client), settings.policy_directory
                ).evaluate_identity(identity)
    except (FileNotFoundError, SQLAlchemyError, ValueError) as error:
        print(f"Policy evaluation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.errors == 0 else 1


def run_security_gate(output_directory: str) -> int:
    settings = get_settings()
    try:
        with OpaClient(settings.opa_url) as engine:
            result = SecurityGateService(
                engine=engine,
                policy_directory=settings.policy_directory,
                control_directory=Path("controls"),
                output_directory=Path(output_directory),
            ).run()
    except (OpaEvaluationError, OSError, SecurityGateError, ValueError) as error:
        print(f"Security gate failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "pass" if result.passed else "fail",
                "fixtures": result.fixture_count,
                "fixture_failures": result.fixture_failures,
                "controls": result.control_count,
                "control_failures": result.control_failures,
                "policy_version": result.policy_version,
                "report_json": str(result.report_json),
                "report_markdown": str(result.report_markdown),
            },
            sort_keys=True,
        )
    )
    return 0 if result.passed else 1


def apply_drift_demo(tenant_id: str) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            result = DriftScenarioService(session).apply()
    except (DemoScenarioError, SQLAlchemyError, ValueError) as error:
        print(f"Drift demo failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def assess_risk(tenant_id: str, username: str) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            identity = IdentityRepository(session).get_by_username(username)
            if identity is None:
                print(f"Risk assessment failed: identity {username} was not found", file=sys.stderr)
                return 1
            result = RiskAnalyticsService(session).assess(identity)
    except (SQLAlchemyError, ValueError) as error:
        print(f"Risk assessment failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "assessment_id": str(result.assessment_id),
                "score": result.score,
                "level": result.level.value,
                "findings": result.findings,
                "model_version": result.model_version,
            },
            sort_keys=True,
        )
    )
    return 0


def run_peer_anomaly(tenant_id: str, username: str) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            identity = IdentityRepository(session).get_by_username(username)
            if identity is None:
                print(f"Peer anomaly failed: identity {username} was not found", file=sys.stderr)
                return 1
            result = PeerAnomalyService(session).run(identity)
    except (SQLAlchemyError, ValueError) as error:
        print(f"Peer anomaly failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "run_id": str(result.run_id),
                "result_id": str(result.result_id),
                "is_anomaly": result.is_anomaly,
                "decision_score": result.decision_score,
                "training_fingerprint": result.training_fingerprint,
                "peer_anomaly_count": result.peer_anomaly_count,
                "cohort_source": result.cohort_source,
                "drift_detected": result.drift_detected,
                "advisory_only": True,
            },
            sort_keys=True,
        )
    )
    return 0


def open_review(
    tenant_id: str, username: str, actor: str, owner: str | None, due_days: int
) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            identity = IdentityRepository(session).get_by_username(username)
            if identity is None:
                raise ValueError(f"identity {username} was not found")
            result = RemediationService(session).open_for_latest_evidence(
                identity, actor=actor, owner=owner, due_days=due_days
            )
    except (SQLAlchemyError, ValueError) as error:
        print(f"Open review failed: {error}", file=sys.stderr)
        return 1
    payload = {"case_id": str(result.case_id), "status": result.status.value}
    print(json.dumps(payload, sort_keys=True))
    return 0


def assign_review(
    tenant_id: str, case_id: uuid.UUID, owner: str, actor: str, reason: str
) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            case = load_case(session, case_id)
            if case is None:
                raise ValueError(f"review {case_id} was not found")
            result = RemediationService(session).assign(case, owner, actor, reason)
    except (SQLAlchemyError, ValueError) as error:
        print(f"Assign review failed: {error}", file=sys.stderr)
        return 1
    payload = {"case_id": str(result.case_id), "status": result.status.value}
    print(json.dumps(payload, sort_keys=True))
    return 0


def decide_review(
    tenant_id: str,
    case_id: uuid.UUID,
    decision: ReviewDecision,
    actor: str,
    reason: str,
) -> int:
    try:
        with get_session_factory(tenant_id)() as session:
            case = load_case(session, case_id)
            if case is None:
                raise ValueError(f"review {case_id} was not found")
            result = RemediationService(session).decide(case, decision, actor, reason)
    except (SQLAlchemyError, ValueError) as error:
        print(f"Decide review failed: {error}", file=sys.stderr)
        return 1
    destructive = decision in (ReviewDecision.REVOKE, ReviewDecision.EXTEND)
    payload = {
        "case_id": str(result.case_id),
        "status": result.status.value,
        "resolution": result.resolution.value if result.resolution else None,
        "execution_status": "pending" if destructive else "not_required",
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def run_monitoring_slot(
    tenant_id: str, username: str, schedule_key: str, requested_by: str
) -> int:
    settings = get_settings()
    try:
        with (
            get_session_factory(tenant_id)() as session,
            KeycloakCollector(settings) as collector,
            OpaClient(settings.opa_url) as engine,
        ):
            def identity() -> Identity:
                record = IdentityRepository(session).get_by_username(username)
                if record is None:
                    raise ValueError(f"identity {username} was not found after synchronization")
                return record

            def synchronize() -> dict:
                return asdict(IdentitySyncService(session).sync(collector.collect()))

            def synchronize_github() -> dict:
                service = GitHubSyncService(session)
                checkpoint = service.checkpoint(settings.github_org)
                cache = checkpoint.endpoint_cache if checkpoint else None
                with GitHubCollector(settings) as github:
                    return asdict(service.sync(github.collect(cache)))

            def synchronize_azure() -> dict:
                with AzureCollector(settings) as azure:
                    return asdict(AzureSyncService(session).sync(azure.collect()))

            def provenance() -> dict:
                entitlements = ProvenanceService(session).materialize_identity(identity())
                session.commit()
                return {"active_entitlements": len(entitlements)}

            def policies() -> dict:
                service = PolicyEvaluationService(
                    session, OpaAuthorizationAdapter(engine), settings.policy_directory
                )
                return asdict(service.evaluate_identity(identity()))

            def risk() -> dict:
                result = RiskAnalyticsService(session).assess(identity())
                return {
                    "assessment_id": str(result.assessment_id),
                    "score": result.score,
                    "level": result.level.value,
                    "findings": result.findings,
                    "model_version": result.model_version,
                }

            def anomaly() -> dict:
                result = PeerAnomalyService(session).run(identity())
                return {
                    "run_id": str(result.run_id),
                    "is_anomaly": result.is_anomaly,
                    "cohort_source": result.cohort_source,
                    "drift_detected": result.drift_detected,
                }

            def review() -> dict:
                result = RemediationService(session).open_for_latest_evidence(
                    identity(), actor="athena-monitoring"
                )
                return {"case_id": str(result.case_id), "status": result.status.value}

            operations = [
                ("identity_sync", synchronize),
            ]
            if settings.github_org and settings.github_token.get_secret_value():
                operations.append(("github_sync", synchronize_github))
            if settings.azure_enabled:
                operations.append(("azure_rbac_sync", synchronize_azure))
            operations.extend([
                ("provenance", provenance), ("policy_evaluation", policies),
                ("risk_assessment", risk), ("peer_anomaly", anomaly), ("review", review),
            ])
            result = MonitoringService(
                session,
                lease_duration=timedelta(seconds=settings.monitoring_lease_seconds),
            ).run(schedule_key, requested_by, operations)
    except (
        AzureCollectionError,
        KeycloakCollectionError,
        MonitoringError,
        OpaEvaluationError,
        SQLAlchemyError,
        ValueError,
    ) as error:
        print(f"Monitoring failed: {error}", file=sys.stderr)
        return 1
    payload = {
        "run_id": str(result.run_id),
        "schedule_key": result.schedule_key,
        "status": result.status.value,
        "attempt": result.attempt,
        "steps_completed": result.steps_completed,
        "idempotent_replay": result.idempotent_replay,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0


def monitoring_loop(
    tenant_id: str, username: str, interval_seconds: int, requested_by: str
) -> int:
    if interval_seconds < 60:
        print("Monitoring interval must be at least 60 seconds", file=sys.stderr)
        return 1
    while True:
        now = datetime.now(UTC)
        slot = int(now.timestamp()) // interval_seconds * interval_seconds
        schedule_key = f"interval-{interval_seconds}:{slot}"
        result = run_monitoring_slot(tenant_id, username, schedule_key, requested_by)
        if result != 0:
            return result
        time.sleep(interval_seconds)


def tenant_inventory() -> int:
    try:
        with get_administrative_session_factory()() as session:
            snapshot = capture_tenant_inventory(session)
    except (SQLAlchemyError, TenantInventoryError) as error:
        print(f"Tenant inventory failed: {error}", file=sys.stderr)
        return 1
    print(snapshot.model_dump_json())
    return 0


def tenant_backfill_plan(approval_file: Path) -> int:
    try:
        approval = load_bootstrap_approval(approval_file)
        with get_administrative_session_factory()() as session:
            plan = build_bootstrap_backfill_plan(session, approval)
    except (
        OSError,
        ValueError,
        SQLAlchemyError,
        TenantInventoryError,
        TenantTransitionError,
    ) as error:
        print(f"Tenant backfill plan failed: {error}", file=sys.stderr)
        return 1
    print(plan.model_dump_json())
    return 0


def tenant_backfill(approval_file: Path, confirmed_plan_sha256: str) -> int:
    try:
        approval = load_bootstrap_approval(approval_file)
        with get_administrative_session_factory().begin() as session:
            result = execute_bootstrap_backfill(
                session,
                approval,
                confirmed_plan_sha256=confirmed_plan_sha256,
            )
    except (
        OSError,
        ValueError,
        SQLAlchemyError,
        TenantInventoryError,
        TenantTransitionError,
    ) as error:
        print(f"Tenant backfill failed: {error}", file=sys.stderr)
        return 1
    print(result.model_dump_json())
    return 0


def tenant_integrity() -> int:
    try:
        with get_administrative_session_factory()() as session:
            report = inspect_tenant_integrity(session)
    except (SQLAlchemyError, TenantIntegrityError) as error:
        print(f"Tenant integrity inspection failed: {error}", file=sys.stderr)
        return 1
    print(report.model_dump_json())
    return 0


def tenant_constraint_plan() -> int:
    try:
        with get_administrative_session_factory()() as session:
            integrity = inspect_tenant_integrity(session)
            plan = build_tenant_constraint_plan(integrity)
    except (SQLAlchemyError, TenantIntegrityError) as error:
        print(f"Tenant constraint plan failed: {error}", file=sys.stderr)
        return 1
    print(plan.model_dump_json())
    return 0


def tenant_rls_plan() -> int:
    try:
        with get_administrative_session_factory()() as session:
            integrity = inspect_tenant_integrity(session)
            constraints = build_tenant_constraint_plan(integrity)
            plan = build_tenant_rls_plan(constraints)
    except (SQLAlchemyError, TenantIntegrityError) as error:
        print(f"Tenant RLS plan failed: {error}", file=sys.stderr)
        return 1
    print(plan.model_dump_json())
    return 0


def connector_scope_plan(
    *,
    action: str,
    tenant_id: str,
    connector: str,
    scope: str,
    approval_reference: str,
    authorized_by: str,
    authorized_at: datetime,
    reason: str | None,
) -> int:
    try:
        with get_administrative_session_factory()() as session:
            administration = ConnectorAdministration(session)
            if action == "approve":
                plan = administration.plan_approval(
                    tenant_id=tenant_id,
                    connector=connector,
                    scope=scope,
                    approval_reference=approval_reference,
                    authorized_by=authorized_by,
                    authorized_at=authorized_at,
                )
            else:
                plan = administration.plan_revocation(
                    tenant_id=tenant_id,
                    connector=connector,
                    scope=scope,
                    approval_reference=approval_reference,
                    authorized_by=authorized_by,
                    authorized_at=authorized_at,
                    reason=reason or "",
                )
    except (ConnectorAdministrationError, SQLAlchemyError, ValueError) as error:
        print(f"Connector scope planning failed: {error}", file=sys.stderr)
        return 1
    print(plan.model_dump_json())
    return 0


def apply_connector_scope_plan(plan_file: Path, confirmed_plan_sha256: str) -> int:
    try:
        plan = ConnectorScopeChangePlan.model_validate_json(plan_file.read_text(encoding="utf-8"))
        with get_administrative_session_factory().begin() as session:
            result = ConnectorAdministration(session).apply(
                plan, confirmed_plan_sha256=confirmed_plan_sha256
            )
    except (ConnectorAdministrationError, OSError, SQLAlchemyError, ValueError) as error:
        print(f"Connector scope application failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"id": str(result.id), "plan_sha256": plan.plan_sha256}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="athena", description="Athena operational commands")
    subcommands = parser.add_subparsers(dest="command", required=True)

    def tenant_command(name: str, *, help: str) -> argparse.ArgumentParser:
        command = subcommands.add_parser(name, help=help)
        command.add_argument("--tenant-id", required=True)
        return command

    tenant_command("sync-keycloak", help="Synchronize identities from Keycloak")
    tenant_command(
        "sync-github", help="Synchronize GitHub organization repository permissions"
    )
    tenant_command(
        "sync-azure", help="Synchronize Microsoft Entra identities and Azure RBAC assignments"
    )
    tenant_command(
        "seed-provenance-demo", help="Seed and materialize Alice's authorization scenario"
    )
    tenant_command(
        "project-attack-graph", help="Project active PostgreSQL provenance into Neo4j"
    )
    evaluate_parser = tenant_command(
        "evaluate-policies", help="Evaluate active entitlements through OPA"
    )
    evaluate_parser.add_argument("--username", default="alice")
    gate_parser = subcommands.add_parser(
        "security-gate", help="Run deterministic policy fixtures and control validation"
    )
    gate_parser.add_argument("--output-directory", default="artifacts/security-gate")
    tenant_command(
        "apply-drift-demo", help="Apply Alice's controlled Engineering-to-Security transfer"
    )
    risk_parser = tenant_command(
        "assess-risk", help="Calculate an explainable access-decay assessment"
    )
    risk_parser.add_argument("--username", default="alice")
    anomaly_parser = tenant_command(
        "run-peer-anomaly", help="Run advisory Isolation Forest peer analysis"
    )
    anomaly_parser.add_argument("--username", default="alice")
    open_parser = tenant_command("open-review", help="Open a human access review")
    open_parser.add_argument("--username", default="alice")
    open_parser.add_argument("--actor", required=True)
    open_parser.add_argument("--owner")
    open_parser.add_argument("--due-days", type=int, default=7)
    assign_parser = tenant_command("assign-review", help="Assign a review owner")
    assign_parser.add_argument("--case-id", type=uuid.UUID, required=True)
    assign_parser.add_argument("--owner", required=True)
    assign_parser.add_argument("--actor", required=True)
    assign_parser.add_argument("--reason", required=True)
    decide_parser = tenant_command("decide-review", help="Record a human review decision")
    decide_parser.add_argument("--case-id", type=uuid.UUID, required=True)
    decide_parser.add_argument(
        "--decision", type=ReviewDecision, choices=list(ReviewDecision), required=True
    )
    decide_parser.add_argument("--actor", required=True)
    decide_parser.add_argument("--reason", required=True)
    monitor_parser = tenant_command(
        "monitor-once", help="Run one idempotent continuous-monitoring slot"
    )
    monitor_parser.add_argument("--username", default="alice")
    monitor_parser.add_argument("--schedule-key")
    monitor_parser.add_argument("--requested-by", default="athena-scheduler")
    loop_parser = tenant_command(
        "monitor-loop", help="Run continuous monitoring at a fixed interval"
    )
    loop_parser.add_argument("--username", default="alice")
    loop_parser.add_argument("--interval-seconds", type=int, default=300)
    loop_parser.add_argument("--requested-by", default="athena-scheduler")
    subcommands.add_parser(
        "tenant-inventory", help="Read table counts for bootstrap-tenant approval"
    )
    backfill_parser = subcommands.add_parser(
        "tenant-backfill-plan", help="Validate and print a dry-run bootstrap backfill plan"
    )
    backfill_parser.add_argument(
        "--approval-file", type=Path, default=Path("tenancy/bootstrap-approval.json")
    )
    execute_backfill_parser = subcommands.add_parser(
        "tenant-backfill", help="Execute an approved bootstrap tenant assignment"
    )
    execute_backfill_parser.add_argument(
        "--approval-file", type=Path, default=Path("tenancy/bootstrap-approval.json")
    )
    execute_backfill_parser.add_argument("--confirm-plan-sha256", required=True)
    subcommands.add_parser(
        "tenant-integrity", help="Inspect tenant assignment and relationship readiness"
    )
    subcommands.add_parser(
        "tenant-constraint-plan", help="Build a non-mutating tenant-aware constraint plan"
    )
    subcommands.add_parser("tenant-rls-plan", help="Build a non-mutating fail-closed RLS plan")
    connector_plan_parser = subcommands.add_parser(
        "connector-scope-plan", help="Build a deterministic connector scope change plan"
    )
    connector_plan_parser.add_argument("--action", choices=("approve", "revoke"), required=True)
    connector_plan_parser.add_argument("--tenant-id", required=True)
    connector_plan_parser.add_argument("--connector", required=True)
    connector_plan_parser.add_argument("--scope", required=True)
    connector_plan_parser.add_argument("--approval-reference", required=True)
    connector_plan_parser.add_argument("--authorized-by", required=True)
    connector_plan_parser.add_argument(
        "--authorized-at", type=datetime.fromisoformat, required=True
    )
    connector_plan_parser.add_argument("--reason")
    connector_apply_parser = subcommands.add_parser(
        "connector-scope-apply", help="Apply an exact approved connector scope change plan"
    )
    connector_apply_parser.add_argument("--plan-file", type=Path, required=True)
    connector_apply_parser.add_argument("--confirm-plan-sha256", required=True)
    arguments = parser.parse_args()

    if arguments.command == "sync-keycloak":
        return sync_keycloak(arguments.tenant_id)
    if arguments.command == "sync-github":
        return sync_github(arguments.tenant_id)
    if arguments.command == "sync-azure":
        return sync_azure(arguments.tenant_id)
    if arguments.command == "seed-provenance-demo":
        return seed_provenance_demo(arguments.tenant_id)
    if arguments.command == "project-attack-graph":
        return project_attack_graph(arguments.tenant_id)
    if arguments.command == "evaluate-policies":
        return evaluate_policies(arguments.tenant_id, arguments.username)
    if arguments.command == "security-gate":
        return run_security_gate(arguments.output_directory)
    if arguments.command == "apply-drift-demo":
        return apply_drift_demo(arguments.tenant_id)
    if arguments.command == "assess-risk":
        return assess_risk(arguments.tenant_id, arguments.username)
    if arguments.command == "run-peer-anomaly":
        return run_peer_anomaly(arguments.tenant_id, arguments.username)
    if arguments.command == "open-review":
        return open_review(
            arguments.tenant_id,
            arguments.username,
            arguments.actor,
            arguments.owner,
            arguments.due_days,
        )
    if arguments.command == "assign-review":
        return assign_review(
            arguments.tenant_id,
            arguments.case_id,
            arguments.owner,
            arguments.actor,
            arguments.reason,
        )
    if arguments.command == "decide-review":
        return decide_review(
            arguments.tenant_id,
            arguments.case_id,
            arguments.decision,
            arguments.actor,
            arguments.reason,
        )
    if arguments.command == "monitor-once":
        schedule_key = arguments.schedule_key or datetime.now(UTC).strftime("manual:%Y%m%dT%H%M")
        return run_monitoring_slot(
            arguments.tenant_id, arguments.username, schedule_key, arguments.requested_by
        )
    if arguments.command == "monitor-loop":
        return monitoring_loop(
            arguments.tenant_id,
            arguments.username,
            arguments.interval_seconds,
            arguments.requested_by,
        )
    if arguments.command == "tenant-inventory":
        return tenant_inventory()
    if arguments.command == "tenant-backfill-plan":
        return tenant_backfill_plan(arguments.approval_file)
    if arguments.command == "tenant-backfill":
        return tenant_backfill(arguments.approval_file, arguments.confirm_plan_sha256)
    if arguments.command == "tenant-integrity":
        return tenant_integrity()
    if arguments.command == "tenant-constraint-plan":
        return tenant_constraint_plan()
    if arguments.command == "tenant-rls-plan":
        return tenant_rls_plan()
    if arguments.command == "connector-scope-plan":
        return connector_scope_plan(
            action=arguments.action,
            tenant_id=arguments.tenant_id,
            connector=arguments.connector,
            scope=arguments.scope,
            approval_reference=arguments.approval_reference,
            authorized_by=arguments.authorized_by,
            authorized_at=arguments.authorized_at,
            reason=arguments.reason,
        )
    if arguments.command == "connector-scope-apply":
        return apply_connector_scope_plan(arguments.plan_file, arguments.confirm_plan_sha256)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
