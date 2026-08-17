import argparse
import json
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from athena.collectors.keycloak import KeycloakCollectionError, KeycloakCollector
from athena.config import get_settings
from athena.database import get_session_factory
from athena.models import Identity, ReviewDecision
from athena.policy.opa import OpaClient, OpaEvaluationError
from athena.services.demo_scenario import DemoScenarioError, DemoScenarioService
from athena.services.drift_scenario import DriftScenarioService
from athena.services.identity_sync import IdentitySyncService
from athena.services.peer_anomaly import PeerAnomalyService
from athena.services.policy_evaluation import PolicyEvaluationService
from athena.services.remediation import RemediationService, load_case
from athena.services.risk_analytics import RiskAnalyticsService
from athena.services.security_gate import SecurityGateError, SecurityGateService


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


def seed_provenance_demo() -> int:
    try:
        with get_session_factory()() as session:
            result = DemoScenarioService(session).seed()
    except (DemoScenarioError, SQLAlchemyError, ValueError) as error:
        print(f"Provenance demo seed failed: {error}", file=sys.stderr)
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
            with OpaClient(settings.opa_url) as engine:
                result = PolicyEvaluationService(
                    session, engine, settings.policy_directory
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


def main() -> int:
    parser = argparse.ArgumentParser(prog="athena", description="Athena operational commands")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("sync-keycloak", help="Synchronize identities from Keycloak")
    subcommands.add_parser(
        "seed-provenance-demo", help="Seed and materialize Alice's authorization scenario"
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
    arguments = parser.parse_args()

    if arguments.command == "sync-keycloak":
        return sync_keycloak()
    if arguments.command == "seed-provenance-demo":
        return seed_provenance_demo()
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
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
