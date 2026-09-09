"""Two-steward synthetic Keycloak person links, separate from access approval."""

import uuid
from datetime import UTC, datetime, timedelta

from athena.auth import ADMINISTRATOR, authorize
from athena.models import Identity, IdentityType, Person, PersonLink, PersonLinkEvent, Reviewer
from athena.services.bound_reviews import BoundReviewService, utc
from athena.tenant_queries import tenant_select


class PersonLinkService(BoundReviewService):
    def steward(self, principal):
        if self.settings.env == "production":
            raise ValueError("Person-link stewardship is limited to the non-production pilot")
        authorize(principal, ADMINISTRATOR)
        actor = self.actor(principal)
        reviewer = self.session.scalar(
            tenant_select(
                self.session,
                Reviewer,
                Reviewer.issuer == actor["issuer"],
                Reviewer.subject == actor["subject"],
            )
        )
        if reviewer is None:
            raise ValueError("An active registered steward is required")
        return self.eligible(reviewer.id), actor

    def account_reference(self, identity):
        if not identity.active or identity.identity_type != IdentityType.HUMAN:
            raise ValueError("Person links require active human accounts")
        self._fresh(identity.observed_at)
        if identity.source == "keycloak" and self.settings.oidc_identity_source == "keycloak":
            scope = self.settings.oidc_issuer
        elif identity.source == "azure_entra":
            scope = identity.source_metadata.get("tenant_id")
        else:
            raise ValueError("Account authority is unsupported for this pilot")
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("Account directory authority is missing")
        return {
            "id": str(identity.id),
            "source": identity.source,
            "external_id": identity.external_id,
            "scope": scope,
        }

    def propose(self, anchor_id, account_id, evidence_kind, evidence_reference, reason, principal):
        steward, actor = self.steward(principal)
        accounts = {
            item.id: item
            for item in self.session.scalars(
                tenant_select(
                    self.session,
                    Identity,
                    Identity.id.in_([anchor_id, account_id]),
                )
                .order_by(Identity.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        }
        if anchor_id not in accounts or account_id not in accounts:
            raise ValueError("Accounts are unavailable in this tenant")
        anchor, account = accounts[anchor_id], accounts[account_id]
        if anchor.source != "keycloak" or self.settings.oidc_identity_source != "keycloak":
            raise ValueError("The pilot person anchor must be a Keycloak account")
        if anchor.id == account.id:
            raise ValueError("Select a separate provider account")
        if self.session.scalar(
            tenant_select(self.session, Person, Person.identity_id == account.id)
        ):
            raise ValueError("A person anchor cannot be linked as another person's account")
        if self.session.scalar(
            tenant_select(
                self.session,
                PersonLink,
                PersonLink.account_id == anchor.id,
                PersonLink.status.in_(["proposed", "confirmed"]),
            )
        ):
            raise ValueError("A linked account cannot become a different person anchor")
        if steward.identity_id in {anchor.id, account.id}:
            raise ValueError("Steward must be independent of the linked accounts")
        if evidence_kind not in {"synthetic_fixture", "directory_admin_attestation", "hr_record"}:
            raise ValueError("Independent evidence kind is required")
        if len(evidence_reference.strip()) < 10 or len(reason.strip()) < 10:
            raise ValueError("Document the independent evidence reference and reason")
        references = {
            "anchor": self.account_reference(anchor),
            "account": self.account_reference(account),
        }
        person = self.session.scalar(
            tenant_select(self.session, Person, Person.identity_id == anchor.id)
        )
        if person is None:
            person = Person(
                identity_id=anchor.id, issuer=self.settings.oidc_issuer, subject=anchor.external_id
            )
            self.session.add(person)
            self.session.flush()
        if (person.issuer, person.subject) != (self.settings.oidc_issuer, anchor.external_id):
            raise ValueError("Person anchor changed; repair requires independent review")
        link = PersonLink(
            person_id=person.id,
            account_id=account.id,
            status="proposed",
            revision=1,
            expires_at=datetime.now(UTC) + timedelta(days=30),
            snapshot={
                **references,
                "proposer_id": str(steward.id),
                "evidence_kind": evidence_kind,
                "evidence_reference": evidence_reference.strip(),
                "contract": "keycloak-person-link-v1",
            },
        )
        link.events.append(
            PersonLinkEvent(revision=1, action="proposed", actor=actor, reason=reason)
        )
        self.session.add(link)
        self.session.commit()
        return link

    def transition(self, identifier, revision, action, reason, principal):
        steward, actor = self.steward(principal)
        link = self.session.scalar(
            tenant_select(
                self.session,
                PersonLink,
                PersonLink.id == identifier,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if link is None or link.revision != revision:
            raise ValueError("Link unavailable or changed; reload and retry")
        if len(reason.strip()) < 10:
            raise ValueError("A reason of at least 10 characters is required")
        if action in {"confirmed", "rejected"}:
            if link.status != "proposed":
                raise ValueError("Only a proposed link can be confirmed or rejected")
            proposer = self.eligible(uuid.UUID(link.snapshot["proposer_id"]))
            if proposer.id == steward.id:
                raise ValueError("A different steward must review the proposal")
            if action == "confirmed":
                self._fresh(link.created_at)
                if utc(link.expires_at) <= datetime.now(UTC):
                    raise ValueError("Link validity has expired")
                for key in ("anchor", "account"):
                    identity = self.get(Identity, uuid.UUID(link.snapshot[key]["id"]))
                    if identity.id == steward.identity_id:
                        raise ValueError("Steward must be independent of the linked accounts")
                    if self.account_reference(identity) != link.snapshot[key]:
                        raise ValueError(
                            "Account authority changed; reject and propose fresh evidence"
                        )
        elif action == "revoked":
            if link.status not in {"proposed", "confirmed"}:
                raise ValueError("Only a current link can be revoked")
        else:
            raise ValueError("Unsupported link transition")
        link.status = action
        link.revision += 1
        link.events.append(
            PersonLinkEvent(
                revision=link.revision,
                action=action,
                actor=actor,
                reason=reason.strip(),
            )
        )
        self.session.commit()
        return link


def link_packet(link):
    return {
        "id": str(link.id),
        "person_id": str(link.person_id),
        "account_id": str(link.account_id),
        "status": link.status,
        "revision": link.revision,
        "snapshot": link.snapshot,
        "expires_at": utc(link.expires_at).isoformat(),
        "within_validity_window": utc(link.expires_at) > datetime.now(UTC),
        "usable_for_access_approval": False,
        "events": [
            {
                "action": event.action,
                "revision": event.revision,
                "actor": event.actor,
                "reason": event.reason,
                "at": utc(event.occurred_at).isoformat(),
            }
            for event in link.events
        ],
    }
