import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from athena.services.tenant_constraints import (
    TenantConstraintPlan,
    is_complete_tenant_constraint_plan,
)
from athena.tenant_transition import TENANT_TABLES

TENANT_SETTING = "athena.tenant_id"
TENANT_EXPRESSION = "tenant_id = nullif(current_setting('athena.tenant_id', true), '')"


class TenantRlsPolicyPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    table: str
    policy_name: str
    enable_row_level_security: Literal[True] = True
    force_row_level_security: Literal[True] = True
    using_expression: str
    with_check_expression: str


class TenantRlsPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ready", "blocked_by_constraints"]
    database_mutation: Literal[False] = False
    tenant_setting: Literal[TENANT_SETTING] = TENANT_SETTING
    policies: tuple[TenantRlsPolicyPlan, ...]
    session_requirements: tuple[str, ...]
    role_requirements: tuple[str, ...]
    plan_sha256: str


def build_tenant_rls_plan(constraints: TenantConstraintPlan) -> TenantRlsPlan:
    if not is_complete_tenant_constraint_plan(constraints):
        raise ValueError("Tenant constraint plan is incomplete or has an invalid digest")
    policies = tuple(
        TenantRlsPolicyPlan(
            table=table,
            policy_name=f"{table}_tenant_isolation",
            using_expression=TENANT_EXPRESSION,
            with_check_expression=TENANT_EXPRESSION,
        )
        for table in TENANT_TABLES
    )
    facts = {
        "schema_version": "1.0",
        "status": "ready" if constraints.status == "ready" else "blocked_by_constraints",
        "database_mutation": False,
        "tenant_setting": TENANT_SETTING,
        "policies": [policy.model_dump(mode="json") for policy in policies],
        "session_requirements": (
            "Set athena.tenant_id with set_config(..., true) inside every transaction.",
            "Reject database access until a validated tenant context is available.",
            "Never use session-level tenant settings on pooled connections.",
            "Verify unset and empty tenant settings return no scoped rows.",
        ),
        "role_requirements": (
            "The application role must not own scoped tables.",
            "The application role must not have BYPASSRLS or superuser privileges.",
            "FORCE ROW LEVEL SECURITY must remain enabled on every scoped table.",
        ),
    }
    digest = hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return TenantRlsPlan(**facts, plan_sha256=digest)
