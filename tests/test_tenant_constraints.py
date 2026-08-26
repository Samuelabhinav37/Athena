from athena.services.tenant_constraints import (
    build_tenant_constraint_plan,
    is_complete_tenant_constraint_plan,
)
from athena.services.tenant_integrity import TenantIntegrityReport


def _integrity(ready: bool) -> TenantIntegrityReport:
    return TenantIntegrityReport(
        ready_for_tenant_constraints=ready,
        unassigned_rows={} if ready else {"identities": 1},
        relationship_checks=(),
        global_unique_constraints=(),
    )


def test_constraint_plan_is_complete_deterministic_and_non_mutating() -> None:
    first = build_tenant_constraint_plan(_integrity(True))
    second = build_tenant_constraint_plan(_integrity(True))

    assert first == second
    assert first.status == "ready"
    assert first.database_mutation is False
    assert first.unique_changes == ()
    assert first.foreign_key_changes == ()
    assert first.supporting_unique_constraints == ()
    assert len(first.plan_sha256) == 64
    assert is_complete_tenant_constraint_plan(first)


def test_constraint_plan_stays_blocked_until_integrity_is_ready() -> None:
    plan = build_tenant_constraint_plan(_integrity(False))

    assert plan.status == "blocked_by_integrity"
    assert is_complete_tenant_constraint_plan(plan)


def test_constraint_plan_rejects_tampered_content_or_digest() -> None:
    plan = build_tenant_constraint_plan(_integrity(True))

    assert not is_complete_tenant_constraint_plan(plan.model_copy(update={"plan_sha256": "0" * 64}))
