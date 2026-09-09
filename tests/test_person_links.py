import uuid

import pytest
from athena.auth import Principal
from athena.config import Settings
from athena.models import Identity, IdentityType, PersonLinkEvent
from athena.services.person_links import PersonLinkService, link_packet
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from test_risk_analytics import risk_session as _risk_session

risk_session = _risk_session


def steward(name):
    return Principal(
        f"user-{name}", name, frozenset({"athena-administrator"}), {"iss": "https://idp.test"}
    )


@pytest.fixture
def links(risk_session):
    service = PersonLinkService(
        risk_session, Settings(database_url="sqlite://", oidc_issuer="https://idp.test")
    )
    identities = {item.username: item for item in risk_session.scalars(select(Identity))}
    for name in ("bob", "charlie"):
        service.register(identities[name].id, steward("admin"), "Registered pilot steward")
    account = Identity(
        source="azure_entra",
        external_id="account-123",
        username="alice-alt",
        display_name="Alice alternate",
        identity_type=IdentityType.HUMAN,
        active=True,
        source_metadata={"tenant_id": "directory-1"},
    )
    risk_session.add(account)
    risk_session.commit()
    return service, identities["alice"], account


def proposal(links):
    service, anchor, account = links
    return service.propose(
        anchor.id,
        account.id,
        "synthetic_fixture",
        "fixture:alice-person-1",
        "Independently checked pilot record",
        steward("bob"),
    )


def test_two_stewards_confirm_and_revoke_without_rewriting_history(links):
    service = links[0]
    link = proposal(links)
    with pytest.raises(ValueError, match="different steward"):
        service.transition(
            link.id, link.revision, "confirmed", "Confirm pilot evidence", steward("bob")
        )
    service.transition(
        link.id, link.revision, "confirmed", "Confirm pilot evidence", steward("charlie")
    )
    assert link_packet(link)["usable_for_access_approval"] is False
    assert link.status == "confirmed"
    service.transition(
        link.id, link.revision, "revoked", "Correct mistaken person link", steward("bob")
    )
    fresh = proposal(links)
    assert fresh.id != link.id
    assert [event.action for event in link.events] == ["proposed", "confirmed", "revoked"]


def test_confirmation_rejects_changed_authority_and_stale_revision(links):
    service, _, account = links
    link = proposal(links)
    with pytest.raises(ValueError, match="changed"):
        service.transition(link.id, 99, "confirmed", "Confirm pilot evidence", steward("charlie"))
    account.source_metadata = {"tenant_id": "other-directory"}
    service.session.commit()
    with pytest.raises(ValueError, match="authority changed"):
        service.transition(
            link.id, link.revision, "confirmed", "Confirm pilot evidence", steward("charlie")
        )
    assert link.status == "proposed"


def test_current_account_uniqueness_and_event_immutability(links):
    service = links[0]
    link = proposal(links)
    with pytest.raises(IntegrityError):
        proposal(links)
    service.session.rollback()
    event = service.session.scalar(
        select(PersonLinkEvent).where(PersonLinkEvent.link_id == link.id)
    )
    event.reason = "Rewritten evidence"
    with pytest.raises(ValueError, match="immutable"):
        service.session.commit()
    service.session.rollback()


def test_unregistered_and_target_stewards_cannot_propose(links):
    service, anchor, account = links
    with pytest.raises(ValueError, match="registered"):
        service.propose(
            anchor.id,
            account.id,
            "synthetic_fixture",
            "fixture:alice-person-1",
            "Independent pilot evidence",
            steward("unknown"),
        )
    service.register(anchor.id, steward("admin"), "Registered pilot steward")
    with pytest.raises(ValueError, match="independent"):
        service.propose(
            anchor.id,
            account.id,
            "synthetic_fixture",
            "fixture:alice-person-1",
            "Independent pilot evidence",
            steward("alice"),
        )


def test_unknown_link_cannot_be_confirmed(links):
    with pytest.raises(ValueError, match="unavailable"):
        links[0].transition(
            uuid.uuid4(), 1, "confirmed", "Confirm pilot evidence", steward("charlie")
        )


def test_api_two_stewards_and_cross_tenant_lookup(links):
    from athena.auth import get_current_principal
    from athena.config import get_settings
    from athena.database import get_db_session
    from athena.main import app
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session

    service, anchor, account = links
    app.dependency_overrides[get_db_session] = lambda: service.session
    app.dependency_overrides[get_settings] = lambda: service.settings
    app.dependency_overrides[get_current_principal] = lambda: steward("bob")
    try:
        client = TestClient(app)
        response = client.post(
            "/v1/person-links",
            json={
                "anchor_id": str(anchor.id),
                "account_id": str(account.id),
                "evidence_kind": "synthetic_fixture",
                "evidence_reference": "fixture:alice-person-1",
                "reason": "Independent pilot evidence",
            },
        )
        assert response.status_code == 201
        link = response.json()
        body = {
            "revision": link["revision"],
            "action": "confirmed",
            "reason": "Confirm pilot evidence",
        }
        path = f"/v1/person-links/{link['id']}/transition"
        assert client.post(path, json=body).status_code == 409
        app.dependency_overrides[get_current_principal] = lambda: steward("charlie")
        assert client.post(path, json=body).status_code == 200
        assert client.post(path, json=body).status_code == 409
        with Session(bind=service.session.get_bind(), info={"tenant_id": "other-tenant"}) as other:
            app.dependency_overrides[get_db_session] = lambda: other
            assert client.get(f"/v1/person-links?account_id={account.id}").json() == []
    finally:
        app.dependency_overrides.clear()


def test_inactive_proposer_blocks_confirmation(links):
    from athena.models import Reviewer

    service = links[0]
    link = proposal(links)
    proposer = service.session.get(Reviewer, uuid.UUID(link.snapshot["proposer_id"]))
    proposer.active = False
    service.session.commit()
    with pytest.raises(ValueError):
        service.transition(
            link.id, link.revision, "confirmed", "Confirm pilot evidence", steward("charlie")
        )


def test_snapshot_and_person_anchor_cannot_be_rebound(links):
    from athena.models import Person

    service = links[0]
    link = proposal(links)
    link.snapshot = {"replaced": True}
    with pytest.raises(ValueError, match="immutable"):
        service.session.commit()
    service.session.rollback()
    person = service.session.get(Person, link.person_id)
    person.subject = "replacement-subject"
    with pytest.raises(ValueError, match="immutable"):
        service.session.commit()
    service.session.rollback()


def test_person_anchor_cannot_become_someone_elses_account(links):
    service, anchor, account = links
    account.source = "keycloak"
    service.session.commit()
    proposal(links)
    with pytest.raises(ValueError, match="person anchor"):
        service.propose(
            account.id,
            anchor.id,
            "synthetic_fixture",
            "fixture:reverse-link",
            "Independently checked reverse link",
            steward("bob"),
        )


def test_expired_link_cannot_be_confirmed(links, monkeypatch):
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace

    service = links[0]
    link = proposal(links)
    future = datetime.now(UTC) + timedelta(days=31)
    monkeypatch.setattr(
        "athena.services.person_links.datetime", SimpleNamespace(now=lambda zone: future)
    )
    with pytest.raises(ValueError, match="expired"):
        service.transition(
            link.id, link.revision, "confirmed", "Confirm pilot evidence", steward("charlie")
        )
