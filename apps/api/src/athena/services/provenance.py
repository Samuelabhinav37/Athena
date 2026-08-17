import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AccessGrant,
    EffectiveEntitlement,
    GrantSubjectType,
    Identity,
    ProvenanceEdge,
)


def governance_gaps(grant: AccessGrant) -> list[str]:
    gaps = []
    if not grant.business_reason or not grant.business_reason.strip():
        gaps.append("missing_business_reason")
    if grant.approved_by_identity_id is None:
        gaps.append("missing_approval")
    if grant.permission.privileged and grant.expires_at is None:
        gaps.append("missing_expiration")
    return gaps


class ProvenanceService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def materialize_identity(self, identity: Identity) -> list[EffectiveEntitlement]:
        now = datetime.now(UTC)
        group_ids = [group.id for group in identity.groups]
        role_ids = [role.id for role in identity.roles]
        subject_filters = [AccessGrant.identity_id == identity.id]
        if group_ids:
            subject_filters.append(AccessGrant.group_id.in_(group_ids))
        if role_ids:
            subject_filters.append(AccessGrant.role_id.in_(role_ids))

        grants = list(
            self.session.scalars(
                select(AccessGrant)
                .options(
                    selectinload(AccessGrant.permission),
                    selectinload(AccessGrant.role),
                    selectinload(AccessGrant.group),
                )
                .where(
                    or_(*subject_filters),
                    AccessGrant.revoked_at.is_(None),
                    or_(AccessGrant.expires_at.is_(None), AccessGrant.expires_at > now),
                )
                .order_by(AccessGrant.external_id)
            ).unique()
        )

        existing = {
            entitlement.grant_id: entitlement
            for entitlement in self.session.scalars(
                select(EffectiveEntitlement).where(
                    EffectiveEntitlement.identity_id == identity.id
                )
            )
        }
        for entitlement in existing.values():
            entitlement.active = False
            entitlement.deactivated_at = now

        entitlements = []
        for grant in grants:
            entitlement = existing.get(grant.id)
            if entitlement is None:
                entitlement = EffectiveEntitlement(
                    identity_id=identity.id,
                    permission_id=grant.permission_id,
                    grant_id=grant.id,
                )
                self.session.add(entitlement)
                self.session.flush()
            else:
                self.session.execute(
                    delete(ProvenanceEdge).where(
                        ProvenanceEdge.entitlement_id == entitlement.id
                    )
                )
            entitlement.permission_id = grant.permission_id
            entitlement.computed_at = now
            entitlement.active = True
            entitlement.deactivated_at = None
            entitlement.provenance_edges = self._edges(identity, grant)
            entitlements.append(entitlement)

        self.session.flush()
        return entitlements

    @staticmethod
    def _edges(identity: Identity, grant: AccessGrant) -> list[ProvenanceEdge]:
        permission = grant.permission
        resource = permission.resource
        edges = []
        if grant.subject_type == GrantSubjectType.IDENTITY:
            relationship = (
                "reported_effective_permission"
                if grant.source_metadata.get("permission_source") == "calculated"
                else "direct_grant"
            )
            edges.append(
                ProvenanceEdge(
                    sequence=0,
                    from_type="identity",
                    from_id=identity.id,
                    from_label=identity.display_name,
                    relationship_type=relationship,
                    to_type="permission",
                    to_id=permission.id,
                    to_label=permission.name,
                )
            )
        else:
            subject = grant.group if grant.subject_type == GrantSubjectType.GROUP else grant.role
            if subject is None:
                raise ValueError("Grant subject type does not match its subject reference")
            edges.extend(
                [
                    ProvenanceEdge(
                        sequence=0,
                        from_type="identity",
                        from_id=identity.id,
                        from_label=identity.display_name,
                        relationship_type=(
                            "member_of"
                            if grant.subject_type == GrantSubjectType.GROUP
                            else "assigned_role"
                        ),
                        to_type=grant.subject_type.value,
                        to_id=subject.id,
                        to_label=subject.name,
                    ),
                    ProvenanceEdge(
                        sequence=1,
                        from_type=grant.subject_type.value,
                        from_id=subject.id,
                        from_label=subject.name,
                        relationship_type="grants",
                        to_type="permission",
                        to_id=permission.id,
                        to_label=permission.name,
                    ),
                ]
            )
        edges.append(
            ProvenanceEdge(
                sequence=len(edges),
                from_type="permission",
                from_id=permission.id,
                from_label=permission.name,
                relationship_type="applies_to",
                to_type="resource",
                to_id=resource.id,
                to_label=resource.name,
            )
        )
        return edges


def load_identity_entitlements(
    session: Session, identity_id: uuid.UUID
) -> list[EffectiveEntitlement]:
    return list(
        session.scalars(
            select(EffectiveEntitlement)
            .options(
                selectinload(EffectiveEntitlement.provenance_edges),
                selectinload(EffectiveEntitlement.grant).selectinload(AccessGrant.approved_by),
            )
            .where(EffectiveEntitlement.identity_id == identity_id)
            .where(EffectiveEntitlement.active.is_(True))
            .order_by(EffectiveEntitlement.computed_at, EffectiveEntitlement.id)
        ).unique()
    )
