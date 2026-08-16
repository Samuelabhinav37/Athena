from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from athena.models import (
    Base,
    Identity,
    IdentityType,
    PolicyDecision,
    PolicyEvaluation,
    Role,
)
from athena.policy.opa import OpaDecision, OpaEvaluationError
from athena.services.demo_scenario import DemoScenarioService
from athena.services.policy_evaluation import PolicyEvaluationService, hash_policy_bundle
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker


class DeterministicEngine:
    policy_path = "athena/authorization/evaluate"

    def evaluate(self, policy_input: dict[str, Any]) -> OpaDecision:
        if policy_input["permission"]["privileged"]:
            return OpaDecision(
                allow=False,
                violations=[
                    {
                        "code": "UNGOVERNED_PRIVILEGED_ACCESS",
                        "severity": "high",
                        "message": "Privileged access lacks evidence",
                    }
                ],
            )
        return OpaDecision(allow=True, violations=[])


class UnavailableEngine:
    policy_path = "athena/authorization/evaluate"

    def evaluate(self, _: dict[str, Any]) -> OpaDecision:
        raise OpaEvaluationError("OPA unavailable")


@pytest.fixture
def policy_directory(tmp_path: Path) -> Path:
    policy_file = tmp_path / "authorization.rego"
    policy_file.write_text("package athena.authorization\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def policy_session() -> Generator[tuple[Session, Identity]]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        developer = Role(
            source="keycloak",
            external_id="role-developer",
            name="developer",
        )
        alice = Identity(
            source="keycloak",
            external_id="user-alice",
            username="alice",
            identity_type=IdentityType.HUMAN,
            display_name="Alice Johnson",
            department="engineering",
            roles=[developer],
        )
        bob = Identity(
            source="keycloak",
            external_id="user-bob",
            username="bob",
            identity_type=IdentityType.HUMAN,
            display_name="Bob Martinez",
        )
        session.add_all([alice, bob])
        session.commit()
        DemoScenarioService(session).seed()
        yield session, alice
    engine.dispose()


def test_policy_evaluations_are_versioned_and_persisted(
    policy_session: tuple[Session, Identity], policy_directory: Path
) -> None:
    session, alice = policy_session
    result = PolicyEvaluationService(
        session, DeterministicEngine(), policy_directory
    ).evaluate_identity(alice)

    assert result.passed == 2
    assert result.failed == 1
    assert result.errors == 0
    assert result.policy_version == hash_policy_bundle(policy_directory)
    assert session.scalar(select(func.count()).select_from(PolicyEvaluation)) == 3
    production = session.scalar(
        select(PolicyEvaluation).where(PolicyEvaluation.decision == PolicyDecision.FAIL)
    )
    assert production is not None
    assert production.input_snapshot["resource"]["external_id"] == "production-database"
    assert production.violations[0]["code"] == "UNGOVERNED_PRIVILEGED_ACCESS"

    DemoScenarioService(session).seed()
    assert session.scalar(select(func.count()).select_from(PolicyEvaluation)) == 3


def test_policy_engine_failure_is_recorded_as_fail_closed_evidence(
    policy_session: tuple[Session, Identity], policy_directory: Path
) -> None:
    session, alice = policy_session
    result = PolicyEvaluationService(
        session, UnavailableEngine(), policy_directory
    ).evaluate_identity(alice)

    assert result == result.__class__(
        passed=0,
        failed=0,
        errors=3,
        policy_version=hash_policy_bundle(policy_directory),
    )
    evaluations = list(session.scalars(select(PolicyEvaluation)))
    assert all(evaluation.decision == PolicyDecision.ERROR for evaluation in evaluations)
    assert all(
        evaluation.violations[0]["code"] == "POLICY_ENGINE_UNAVAILABLE"
        for evaluation in evaluations
    )


def test_policy_evaluations_are_immutable(
    policy_session: tuple[Session, Identity], policy_directory: Path
) -> None:
    session, alice = policy_session
    PolicyEvaluationService(session, DeterministicEngine(), policy_directory).evaluate_identity(
        alice
    )
    evaluation = session.scalar(select(PolicyEvaluation))
    assert evaluation is not None
    evaluation.engine = "tampered"

    with pytest.raises(ValueError, match="immutable"):
        session.commit()
    session.rollback()
