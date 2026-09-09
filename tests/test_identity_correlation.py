import uuid

import pytest
from athena.models import Identity, IdentityType
from athena.services.identity_correlation import inspect_candidates
from sqlalchemy import select
from test_risk_analytics import risk_session as _risk_session

risk_session = _risk_session


def account(session, *, tenant="test-tenant", active=True, kind=IdentityType.HUMAN):
    record = Identity(
        tenant_id=tenant,
        source="azure",
        external_id=str(uuid.uuid4()),
        username="different-name",
        display_name="Renamed Person",
        email="alice@example.test",
        identity_type=kind,
        active=active,
    )
    session.add(record)
    session.commit()
    return record


def target(session):
    record = session.scalar(select(Identity).where(Identity.username == "alice"))
    record.email = " Alice@Example.Test "
    session.commit()
    return record


def test_candidate_preserves_accounts_and_never_confirms_link(risk_session):
    identity = target(risk_session)
    other = account(risk_session)
    result = inspect_candidates(risk_session, identity, "keycloak")
    assert result["state"] == "candidate"
    assert result["link_confirmed"] is False
    assert result["candidates"][0]["identity_id"] == str(other.id)
    assert result["candidates"][0]["requires_independent_confirmation"] is True
    assert identity.id != other.id
    assert not risk_session.new and not risk_session.dirty


def test_recycled_inactive_email_remains_ambiguous_even_on_one_item_page(risk_session):
    identity = target(risk_session)
    account(risk_session)
    account(risk_session, active=False)
    result = inspect_candidates(risk_session, identity, "keycloak", limit=1)
    assert result["state"] == "ambiguous"
    assert result["has_more"] is True
    assert len(result["candidates"]) == 1


def test_cross_tenant_and_workload_lookalikes_are_not_person_candidates(risk_session):
    identity = target(risk_session)
    account(risk_session, tenant="other-tenant")
    account(risk_session, kind=IdentityType.WORKLOAD)
    assert inspect_candidates(risk_session, identity, "keycloak")["state"] == "unlinked"


@pytest.mark.parametrize("email", [None, "", "not-an-email", "a@b@c"])
def test_missing_contact_evidence_is_not_a_name_match(risk_session, email):
    identity = target(risk_session)
    account(risk_session)
    identity.email = email
    risk_session.commit()
    assert (
        inspect_candidates(risk_session, identity, "keycloak")["state"] == "insufficient_evidence"
    )


def test_workload_and_inactive_targets_do_not_generate_person_candidates(risk_session):
    workload = account(risk_session, kind=IdentityType.WORKLOAD)
    inactive = account(risk_session, active=False)
    assert (
        inspect_candidates(risk_session, workload, "keycloak")["state"]
        == "unsupported_account_type"
    )
    assert inspect_candidates(risk_session, inactive, "keycloak")["state"] == "inactive_account"


def test_candidate_api_requires_tenant_visible_identity(risk_session):
    from athena.auth import Principal, get_current_principal
    from athena.config import Settings, get_settings
    from athena.database import get_db_session
    from athena.main import app
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session

    identity = target(risk_session)
    account(risk_session)
    app.dependency_overrides[get_db_session] = lambda: risk_session
    app.dependency_overrides[get_settings] = lambda: Settings(database_url="sqlite://")
    app.dependency_overrides[get_current_principal] = lambda: Principal(
        "viewer",
        "viewer",
        frozenset({"athena-viewer"}),
        {},
    )
    try:
        client = TestClient(app)
        path = f"/v1/identities/{identity.id}/correlation-candidates"
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()["link_confirmed"] is False
        assert client.get(path + "?limit=201").status_code == 422
        with Session(bind=risk_session.get_bind(), info={"tenant_id": "other-tenant"}) as other:
            app.dependency_overrides[get_db_session] = lambda: other
            assert client.get(path).status_code == 404
    finally:
        app.dependency_overrides.clear()
