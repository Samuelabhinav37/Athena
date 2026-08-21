import argparse
import json
import sys
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from athena.collectors.azure import AzureCollectionError, AzureCollector
from athena.collectors.github import GitHubCollectionError, GitHubCollector
from athena.collectors.keycloak import KeycloakCollectionError, KeycloakCollector
from athena.config import get_settings
from athena.database import get_session_factory
from athena.models import Identity, ReviewDecision
from athena.policy.opa import OpaAuthorizationAdapter, OpaClient, OpaEvaluationError
from athena.services.attack_paths import AttackPathError, Neo4jAttackPathAdapter, build_projection
from athena.services.azure_sync import AzureSyncService
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
from athena.services.tenant_inventory import TenantInventoryError, capture_tenant_inventory


def sync_keycloak() -> int:
    try:
        settings = get_settings()
        with KeycloakCollector(settings) as collector:
            records = collector.collect()
        with get_session_factory()() as session:
            result = IdentitySyncService(session).sync(records)
    except (KeycloakCollectionError, SQLAlchemyError) as error:
        print(f"Keycloak synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def sync_github() -> int:
    try:
        settings = get_settings()
        with get_session_factory()() as session:
            service = GitHubSyncService(session)
            checkpoint = service.checkpoint(settings.github_org)
            cache = checkpoint.endpoint_cache if checkpoint else None
            with GitHubCollector(settings) as collector:
                snapshot = collector.collect(cache)
            result = service.sync(snapshot)
    except (GitHubCollectionError, SQLAlchemyError, ValueError) as error:
        print(f"GitHub synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def sync_azure() -> int:
    try:
        settings = get_settings()
        with get_session_factory()() as session:
            with AzureCollector(settings) as collector:
                snapshot = collector.collect()
            result = AzureSyncService(session).sync(snapshot)
    except (AzureCollectionError, SQLAlchemyError, ValueError) as error:
        print(f"Azure synchronization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


def seed_provenance_demo() -> int:
    try:
        with get_session_factory()() as session:
            result = DemoScenarioService(session).seed()
    except (DemoScenarioError, SQLAlchemyError, ValueError) as error:
        print(f"Provenance demo seed failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def project_attack_graph() -> int:
    settings = get_settings()
    try:
        with get_session_factory()() as session:
            projection = build_projection(session)
        with Neo4jAttackPathAdapter(settings) as adapter:
            result = adapter.project(projection)
    except (AttackPathError, SQLAlchemyError, ValueError) as error:
        print(f"Attack graph projection failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def evaluate_policies(username: str) -> int:
    settings = get_settings()
    try:
        with get_session_factory()() as session:
            identity = session.scalar(select(Identity).where(Identity.username == username))
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


def apply_drift_demo() -> int:
    try:
        with get_session_factory()() as session:
            result = DriftScenarioService(session).apply()
    except (DemoScenarioError, SQLAlchemyError, ValueError) as error:
        print(f"Drift demo failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def assess_risk(username: str) -> int:
    try:
        with get_session_factory()() as session:
            identity = session.scalar(select(Identity).where(Identity.username == username))
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


def run_peer_anomaly(username: str) -> int:
    try:
        with get_session_factory()() as session:
            identity = session.scalar(select(Identity).where(Identity.username == username))
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


def open_review(username: str, actor: str, owner: str | None, due_days: int) -> int:
    try:
        with get_session_factory()() as session:
            identity = session.scalar(select(Identity).where(Identity.username == username))
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


def assign_review(case_id: uuid.UUID, owner: str, actor: str, reason: str) -> int:
    try:
        with get_session_factory()() as session:
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
    case_id: uuid.UUID, decision: ReviewDecision, actor: str, reason: str
) -> int:
    try:
        with get_session_factory()() as session:
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


def run_monitoring_slot(username: str, schedule_key: str, requested_by: str) -> int:
    settings = get_settings()
    try:
        with (
            get_session_factory()() as session,
            KeycloakCollector(settings) as collector,
            OpaClient(settings.opa_url) as engine,
        ):
            def identity() -> Identity:
                record = session.scalar(select(Identity).where(Identity.username == username))
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
            result = MonitoringService(session).run(schedule_key, requested_by, operations)
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


def monitoring_loop(username: str, interval_seconds: int, requested_by: str) -> int:
    if interval_seconds < 60:
        print("Monitoring interval must be at least 60 seconds", file=sys.stderr)
        return 1
    while True:
        now = datetime.now(UTC)
        slot = int(now.timestamp()) // interval_seconds * interval_seconds
        schedule_key = f"interval-{interval_seconds}:{slot}"
        result = run_monitoring_slot(username, schedule_key, requested_by)
        if result != 0:
            return result
        time.sleep(interval_seconds)


def tenant_inventory() -> int:
    try:
        with get_session_factory()() as session:
            snapshot = capture_tenant_inventory(session)
    except (SQLAlchemyError, TenantInventoryError) as error:
        print(f"Tenant inventory failed: {error}", file=sys.stderr)
        return 1
    print(snapshot.model_dump_json())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="athena", description="Athena operational commands")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("sync-keycloak", help="Synchronize identities from Keycloak")
    subcommands.add_parser(
        "sync-github", help="Synchronize GitHub organization repository permissions"
    )
    subcommands.add_parser(
        "sync-azure", help="Synchronize Microsoft Entra identities and Azure RBAC assignments"
    )
    subcommands.add_parser(
        "seed-provenance-demo", help="Seed and materialize Alice's authorization scenario"
    )
    subcommands.add_parser(
        "project-attack-graph", help="Project active PostgreSQL provenance into Neo4j"
    )
    evaluate_parser = subcommands.add_parser(
        "evaluate-policies", help="Evaluate active entitlements through OPA"
    )
    evaluate_parser.add_argument("--username", default="alice")
    gate_parser = subcommands.add_parser(
        "security-gate", help="Run deterministic policy fixtures and control validation"
    )
    gate_parser.add_argument("--output-directory", default="artifacts/security-gate")
    subcommands.add_parser(
        "apply-drift-demo", help="Apply Alice's controlled Engineering-to-Security transfer"
    )
    risk_parser = subcommands.add_parser(
        "assess-risk", help="Calculate an explainable access-decay assessment"
    )
    risk_parser.add_argument("--username", default="alice")
    anomaly_parser = subcommands.add_parser(
        "run-peer-anomaly", help="Run advisory Isolation Forest peer analysis"
    )
    anomaly_parser.add_argument("--username", default="alice")
    open_parser = subcommands.add_parser("open-review", help="Open a human access review")
    open_parser.add_argument("--username", default="alice")
    open_parser.add_argument("--actor", required=True)
    open_parser.add_argument("--owner")
    open_parser.add_argument("--due-days", type=int, default=7)
    assign_parser = subcommands.add_parser("assign-review", help="Assign a review owner")
    assign_parser.add_argument("--case-id", type=uuid.UUID, required=True)
    assign_parser.add_argument("--owner", required=True)
    assign_parser.add_argument("--actor", required=True)
    assign_parser.add_argument("--reason", required=True)
    decide_parser = subcommands.add_parser("decide-review", help="Record a human review decision")
    decide_parser.add_argument("--case-id", type=uuid.UUID, required=True)
    decide_parser.add_argument(
        "--decision", type=ReviewDecision, choices=list(ReviewDecision), required=True
    )
    decide_parser.add_argument("--actor", required=True)
    decide_parser.add_argument("--reason", required=True)
    monitor_parser = subcommands.add_parser(
        "monitor-once", help="Run one idempotent continuous-monitoring slot"
    )
    monitor_parser.add_argument("--username", default="alice")
    monitor_parser.add_argument("--schedule-key")
    monitor_parser.add_argument("--requested-by", default="athena-scheduler")
    loop_parser = subcommands.add_parser(
        "monitor-loop", help="Run continuous monitoring at a fixed interval"
    )
    loop_parser.add_argument("--username", default="alice")
    loop_parser.add_argument("--interval-seconds", type=int, default=300)
    loop_parser.add_argument("--requested-by", default="athena-scheduler")
    subcommands.add_parser(
        "tenant-inventory", help="Read table counts for bootstrap-tenant approval"
    )
    arguments = parser.parse_args()

    if arguments.command == "sync-keycloak":
        return sync_keycloak()
    if arguments.command == "sync-github":
        return sync_github()
    if arguments.command == "sync-azure":
        return sync_azure()
    if arguments.command == "seed-provenance-demo":
        return seed_provenance_demo()
    if arguments.command == "project-attack-graph":
        return project_attack_graph()
    if arguments.command == "evaluate-policies":
        return evaluate_policies(arguments.username)
    if arguments.command == "security-gate":
        return run_security_gate(arguments.output_directory)
    if arguments.command == "apply-drift-demo":
        return apply_drift_demo()
    if arguments.command == "assess-risk":
        return assess_risk(arguments.username)
    if arguments.command == "run-peer-anomaly":
        return run_peer_anomaly(arguments.username)
    if arguments.command == "open-review":
        return open_review(arguments.username, arguments.actor, arguments.owner, arguments.due_days)
    if arguments.command == "assign-review":
        return assign_review(arguments.case_id, arguments.owner, arguments.actor, arguments.reason)
    if arguments.command == "decide-review":
        return decide_review(
            arguments.case_id, arguments.decision, arguments.actor, arguments.reason
        )
    if arguments.command == "monitor-once":
        schedule_key = arguments.schedule_key or datetime.now(UTC).strftime("manual:%Y%m%dT%H%M")
        return run_monitoring_slot(arguments.username, schedule_key, arguments.requested_by)
    if arguments.command == "monitor-loop":
        return monitoring_loop(
            arguments.username, arguments.interval_seconds, arguments.requested_by
        )
    if arguments.command == "tenant-inventory":
        return tenant_inventory()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
