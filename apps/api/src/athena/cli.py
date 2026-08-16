import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from athena.collectors.keycloak import KeycloakCollectionError, KeycloakCollector
from athena.config import get_settings
from athena.database import get_session_factory
from athena.models import Identity
from athena.policy.opa import OpaClient, OpaEvaluationError
from athena.services.demo_scenario import DemoScenarioError, DemoScenarioService
from athena.services.identity_sync import IdentitySyncService
from athena.services.policy_evaluation import PolicyEvaluationService
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
    arguments = parser.parse_args()

    if arguments.command == "sync-keycloak":
        return sync_keycloak()
    if arguments.command == "seed-provenance-demo":
        return seed_provenance_demo()
    if arguments.command == "evaluate-policies":
        return evaluate_policies(arguments.username)
    if arguments.command == "security-gate":
        return run_security_gate(arguments.output_directory)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
