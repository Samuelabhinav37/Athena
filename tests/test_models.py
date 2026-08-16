from athena.models import Base
from sqlalchemy import create_engine


def test_canonical_schema_contains_identity_backbone_tables() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    assert set(Base.metadata.tables) == {
        "anomaly_model_runs",
        "anomaly_results",
        "access_grants",
        "access_observations",
        "audit_events",
        "effective_entitlements",
        "groups",
        "identities",
        "identity_groups",
        "identity_roles",
        "permissions",
        "policy_evaluations",
        "provenance_edges",
        "resources",
        "risk_assessments",
        "risk_findings",
        "role_transitions",
        "roles",
    }
