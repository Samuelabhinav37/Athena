from athena.models import Base
from sqlalchemy import ForeignKeyConstraint, create_engine


def test_canonical_schema_contains_identity_backbone_tables() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    assert set(Base.metadata.tables) == {
        "anomaly_model_runs",
        "anomaly_results",
        "access_grants",
        "access_observations",
        "audit_events",
        "connector_checkpoints",
        "connector_scope_bindings",
        "connector_scope_revocations",
        "effective_entitlements",
        "groups",
        "identities",
        "identity_groups",
        "identity_roles",
        "monitoring_runs",
        "monitoring_steps",
        "permissions",
        "policy_evaluations",
        "provenance_edges",
        "remediation_execution_events",
        "remediation_executions",
        "resources",
        "risk_assessments",
            "risk_findings",
            "role_transitions",
            "roles",
            "tenants",
            "review_cases",
        "review_events",
    }


def test_access_grant_requester_and_approver_references_restrict_identity_deletion() -> None:
    constraints = {
        constraint.name: constraint.ondelete
        for constraint in Base.metadata.tables["access_grants"].constraints
        if isinstance(constraint, ForeignKeyConstraint)
    }

    assert constraints["fk_access_grants_tenant_requested_by_identity_id_identities"] == "RESTRICT"
    assert constraints["fk_access_grants_tenant_approved_by_identity_id_identities"] == "RESTRICT"
