import pytest
from athena.tenancy import (
    TENANT_ISOLATION_PLAN,
    TenantContext,
    TenantIsolationError,
    TenantIsolationPlan,
    TenantScopedReference,
    require_tenant_access,
)
from pydantic import ValidationError


def test_same_tenant_reference_is_allowed_and_cross_tenant_fails_closed() -> None:
    context = TenantContext(
        tenant_id="acme-001", subject="user-alice", source="oidc_claim"
    )
    own = TenantScopedReference(
        tenant_id="acme-001", object_type="identity", object_id="alice"
    )
    foreign = own.model_copy(update={"tenant_id": "globex-001"})

    assert require_tenant_access(context, own) == own
    with pytest.raises(TenantIsolationError, match="Cross-tenant access is forbidden"):
        require_tenant_access(context, foreign)


def test_tenant_context_rejects_missing_noncanonical_and_unknown_values() -> None:
    with pytest.raises(ValidationError, match="tenant_id"):
        TenantContext(subject="alice", source="oidc_claim")
    with pytest.raises(ValidationError, match="tenant_id"):
        TenantContext(tenant_id="Acme", subject="alice", source="oidc_claim")
    with pytest.raises(ValidationError, match="Extra inputs"):
        TenantContext(
            tenant_id="acme", subject="alice", source="oidc_claim", administrator_bypass=True
        )


def test_isolation_plan_is_complete_and_forbids_global_admin_bypass() -> None:
    plan = TENANT_ISOLATION_PLAN

    assert plan.status == "design_only"
    assert plan.current_mode == "single_tenant"
    assert plan.global_administrator_bypass is False
    assert len(plan.invariants) == 7
    assert "audit_events" in plan.migration_entities
    assert any("row-level security" in blocker for blocker in plan.blockers)

    with pytest.raises(ValidationError, match="global_administrator_bypass"):
        TenantIsolationPlan(
            **plan.model_dump(exclude={"global_administrator_bypass"}),
            global_administrator_bypass=True,
        )
