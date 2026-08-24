import pytest
from athena.services.tenant_constraints import build_tenant_constraint_plan
from athena.services.tenant_integrity import TenantIntegrityReport
from athena.services.tenant_rls import TENANT_EXPRESSION, build_tenant_rls_plan
from athena.tenant_transition import TENANT_TABLES


def _constraints(ready: bool):
    return build_tenant_constraint_plan(
        TenantIntegrityReport(
            ready_for_tenant_constraints=ready,
            unassigned_rows={} if ready else {"identities": 1},
            relationship_checks=(),
            global_unique_constraints=(),
        )
    )


def test_rls_plan_is_complete_fail_closed_and_deterministic() -> None:
    first = build_tenant_rls_plan(_constraints(True))
    second = build_tenant_rls_plan(_constraints(True))

    assert first == second
    assert first.status == "ready"
    assert first.database_mutation is False
    assert tuple(policy.table for policy in first.policies) == TENANT_TABLES
    assert all(policy.force_row_level_security for policy in first.policies)
    assert all(policy.using_expression == TENANT_EXPRESSION for policy in first.policies)
    assert all(policy.with_check_expression == TENANT_EXPRESSION for policy in first.policies)
    assert "current_setting('athena.tenant_id', true)" in TENANT_EXPRESSION
    assert "nullif" in TENANT_EXPRESSION
    assert any("BYPASSRLS" in requirement for requirement in first.role_requirements)
    assert any("pooled" in requirement for requirement in first.session_requirements)
    assert len(first.plan_sha256) == 64


def test_rls_plan_stays_blocked_until_constraints_are_ready() -> None:
    plan = build_tenant_rls_plan(_constraints(False))

    assert plan.status == "blocked_by_constraints"


def test_rls_plan_rejects_incomplete_or_tampered_constraint_plan() -> None:
    constraints = _constraints(True).model_copy(update={"plan_sha256": "0" * 64})

    with pytest.raises(ValueError, match="incomplete or has an invalid digest"):
        build_tenant_rls_plan(constraints)
