"""Versioned person attribution for review evidence; never grants authority."""

from datetime import UTC, datetime, timedelta

from athena.models import Identity, IdentityType, Person, PersonLink
from athena.tenant_queries import tenant_select


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def person_binding(session, settings, identity):
    result = {
        "account_id": str(identity.id),
        "source": identity.source,
        "external_id": identity.external_id,
        "state": "unresolved",
        "canonical_account_id": None,
        "link_id": None,
        "link_revision": None,
    }
    now = datetime.now(UTC)

    def current(account):
        return (
            account.active
            and account.identity_type == IdentityType.HUMAN
            and (timedelta(0) <= now - _utc(account.observed_at) <= timedelta(hours=24))
        )

    def reference(account):
        return {
            "id": str(account.id),
            "source": account.source,
            "external_id": account.external_id,
            "scope": settings.oidc_issuer
            if account.source == "keycloak"
            else account.source_metadata.get("tenant_id"),
        }

    result["authority"] = reference(identity)["scope"]
    link = session.scalar(
        tenant_select(
            session,
            PersonLink,
            PersonLink.account_id == identity.id,
            PersonLink.status.in_(["proposed", "confirmed"]),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if link is not None:
        result.update(
            link_id=str(link.id),
            link_revision=link.revision,
            expires_at=_utc(link.expires_at).isoformat(),
            state="unusable",
        )
        person = session.scalar(tenant_select(session, Person, Person.id == link.person_id))
        anchor = (
            session.scalar(
                tenant_select(
                    session,
                    Identity,
                    Identity.id == person.identity_id,
                )
            )
            if person
            else None
        )
        if (
            link.status == "confirmed"
            and _utc(link.expires_at) > now
            and anchor is not None
            and current(anchor)
            and current(identity)
            and settings.oidc_identity_source == "keycloak"
            and (person.issuer, person.subject) == (settings.oidc_issuer, anchor.external_id)
            and link.snapshot["anchor"] == reference(anchor)
            and link.snapshot["account"] == reference(identity)
        ):
            result.update(
                state="linked", canonical_account_id=str(anchor.id), person_id=str(person.id)
            )
    elif identity.source == settings.oidc_identity_source == "keycloak" and current(identity):
        result.update(state="direct", canonical_account_id=str(identity.id))
    return result


def check_bindings(target, reviewer):
    if target["state"] == "unusable" or reviewer["state"] == "unusable":
        raise ValueError("Person link is pending, expired or invalid; fresh review is required")
    if (
        target["canonical_account_id"] is not None
        and target["canonical_account_id"] == reviewer["canonical_account_id"]
    ):
        raise ValueError("Self-review through another account is prohibited")
