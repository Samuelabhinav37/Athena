from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.collectors.contracts import NormalizedGroup, NormalizedIdentity, NormalizedRole
from athena.models import Group, Identity, Role, utc_now


@dataclass(frozen=True)
class SyncResult:
    identities_created: int
    identities_updated: int
    groups_seen: int
    roles_seen: int


class IdentitySyncService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def sync(self, records: list[NormalizedIdentity]) -> SyncResult:
        created = 0
        updated = 0
        group_keys: set[tuple[str, str]] = set()
        role_keys: set[tuple[str, str]] = set()
        sources = {record.source for record in records}
        self._groups = {
            (group.source, group.external_id): group
            for group in self.session.scalars(select(Group).where(Group.source.in_(sources)))
        }
        self._roles = {
            (role.source, role.external_id): role
            for role in self.session.scalars(select(Role).where(Role.source.in_(sources)))
        }

        for record in records:
            identity = self._identity(record.source, record.external_id)
            if identity is None:
                identity = Identity(
                    source=record.source,
                    external_id=record.external_id,
                    username=record.username,
                    identity_type=record.identity_type,
                    display_name=record.display_name,
                )
                self.session.add(identity)
                created += 1
            else:
                updated += 1

            identity.username = record.username
            identity.identity_type = record.identity_type
            identity.display_name = record.display_name
            identity.email = record.email
            identity.department = record.department
            identity.job_title = record.job_title
            identity.manager_external_id = record.manager_external_id
            identity.active = record.active
            identity.source_metadata = record.source_metadata
            identity.observed_at = utc_now()
            identity.groups = [self._upsert_group(record.source, group) for group in record.groups]
            identity.roles = [self._upsert_role(record.source, role) for role in record.roles]

            group_keys.update((record.source, group.external_id) for group in record.groups)
            role_keys.update((record.source, role.external_id) for role in record.roles)

        self.session.commit()
        return SyncResult(created, updated, len(group_keys), len(role_keys))

    def _identity(self, source: str, external_id: str) -> Identity | None:
        return self.session.scalar(
            select(Identity).where(
                Identity.source == source,
                Identity.external_id == external_id,
            )
        )

    def _upsert_group(self, source: str, record: NormalizedGroup) -> Group:
        key = (source, record.external_id)
        group = self._groups.get(key)
        if group is None:
            group = Group(
                source=source,
                external_id=record.external_id,
                name=record.name,
                path=record.path,
            )
            self.session.add(group)
            self._groups[key] = group
        else:
            group.name = record.name
            group.path = record.path
        return group

    def _upsert_role(self, source: str, record: NormalizedRole) -> Role:
        key = (source, record.external_id)
        role = self._roles.get(key)
        if role is None:
            role = Role(
                source=source,
                external_id=record.external_id,
                name=record.name,
                description=record.description,
            )
            self.session.add(role)
            self._roles[key] = role
        else:
            role.name = record.name
            role.description = record.description
        return role
