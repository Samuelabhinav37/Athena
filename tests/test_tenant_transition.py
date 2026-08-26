from datetime import UTC, datetime

import pytest
from athena.models import Base
from athena.tenant_transition import (
    IMMUTABLE_EVIDENCE_TABLES,
    TENANT_TABLES,
    BootstrapTenantApproval,
    TenantTransitionError,
    build_tenant_transition_plan,
    tenant_inventory_digest,
    validate_observed_inventory,
)
from pydantic import ValidationError


def _counts() -> dict[str, int]:
    return {table: 0 for table in TENANT_TABLES}


def _approval() -> BootstrapTenantApproval:
    return BootstrapTenantApproval(
        tenant_id="athena-bootstrap",
        display_name="Approved existing Athena deployment",
        approval_reference="CHANGE-2026-0001",
        authorized_by="platform-owner",
        approved_at=datetime(2026, 8, 19, 21, 0, tzinfo=UTC),
        expected_preexisting_rows=_counts(),
        inventory_sha256=tenant_inventory_digest(_counts()),
    )


def test_transition_plan_covers_every_model_table_and_is_deterministic() -> None:
    first = build_tenant_transition_plan(_approval())
    second = build_tenant_transition_plan(_approval())

    assert set(first.tables) == set(Base.metadata.tables) - {"tenants"}
    assert first == second
    assert len(first.plan_sha256) == 64
    assert first.status == "review_required"
    assert [phase.sequence for phase in first.phases] == [1, 2, 3, 4, 5, 6]
    assert any(phase.phase_id == "row-level-security" for phase in first.phases)


def test_transition_preserves_all_immutable_evidence_families() -> None:
    plan = build_tenant_transition_plan(_approval())

    assert set(plan.immutable_evidence_tables) == set(IMMUTABLE_EVIDENCE_TABLES)
    bootstrap_phase = next(
        phase for phase in plan.phases if phase.phase_id == "add-bootstrap-scope"
    )
    assert any("triggers" in check for check in bootstrap_phase.required_checks)
    assert any("No row content" in check for check in bootstrap_phase.required_checks)


def test_approval_requires_complete_inventory_and_observed_counts_must_match() -> None:
    incomplete = _counts()
    incomplete.pop("audit_events")
    with pytest.raises(ValidationError, match="inventory table mismatch"):
        BootstrapTenantApproval(
            tenant_id="athena-bootstrap",
            display_name="Existing deployment",
            approval_reference="CHANGE-2026-0001",
            authorized_by="platform-owner",
            approved_at=datetime(2026, 8, 19, 21, 0, tzinfo=UTC),
            expected_preexisting_rows=incomplete,
            inventory_sha256=tenant_inventory_digest(incomplete),
        )

    observed = _counts()
    observed["identities"] = 1
    with pytest.raises(TenantTransitionError, match="differs"):
        validate_observed_inventory(_approval(), observed)

    validate_observed_inventory(_approval(), _counts())
