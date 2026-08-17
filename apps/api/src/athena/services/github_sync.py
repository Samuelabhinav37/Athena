from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.collectors.contracts import NormalizedGroup, NormalizedIdentity
from athena.collectors.github import GitHubSnapshot
from athena.models import (
    AccessGrant,
    AuditEvent,
    ConnectorCheckpoint,
    GrantSubjectType,
    Identity,
    IdentityType,
    Permission,
    Resource,
    ResourceType,
    Sensitivity,
)
from athena.services.identity_sync import IdentitySyncService
from athena.services.provenance import ProvenanceService


@dataclass(frozen=True)
class GitHubSyncResult:
    identities: int
    repositories: int
    permissions: int
    grants_created: int
    grants_updated: int
    grants_revoked: int
    fingerprint: str
    unchanged: bool


class GitHubSyncService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def checkpoint(self, organization: str) -> ConnectorCheckpoint | None:
        return self.session.scalar(
            select(ConnectorCheckpoint).where(
                ConnectorCheckpoint.connector == "github",
                ConnectorCheckpoint.scope == organization,
            )
        )

    def sync(self, snapshot: GitHubSnapshot) -> GitHubSyncResult:
        checkpoint = self.checkpoint(snapshot.organization)
        if checkpoint is not None and checkpoint.fingerprint == snapshot.fingerprint:
            checkpoint.observed_at = datetime.now(UTC)
            checkpoint.endpoint_cache = snapshot.endpoint_cache
            self.session.commit()
            return GitHubSyncResult(
                len(snapshot.members),
                len(snapshot.repositories),
                len(snapshot.permissions),
                0,
                0,
                0,
                snapshot.fingerprint,
                True,
            )
        org_group = NormalizedGroup(
            external_id=f"org:{snapshot.organization}",
            name=snapshot.organization,
            path=f"/github/{snapshot.organization}",
        )
        team_names = {team["id"]: team for team in snapshot.teams}
        teams_by_login: dict[str, list[NormalizedGroup]] = {}
        for membership in snapshot.team_memberships:
            team = team_names[membership["team_id"]]
            teams_by_login.setdefault(membership["login"], []).append(
                NormalizedGroup(
                    external_id=f"team:{team['id']}",
                    name=team["name"],
                    path=f"/github/{snapshot.organization}/teams/{team['slug']}",
                )
            )
        records = [
            NormalizedIdentity(
                source="github",
                external_id=str(member["id"]),
                username=member["login"],
                identity_type=IdentityType.HUMAN,
                display_name=member["login"],
                active=True,
                source_metadata={
                    "html_url": member.get("html_url"),
                    "node_id": member.get("node_id"),
                },
                groups=[org_group, *teams_by_login.get(member["login"], [])],
            )
            for member in snapshot.members
        ]
        IdentitySyncService(self.session).sync(records)
        identities = {
            identity.username: identity
            for identity in self.session.scalars(
                select(Identity).where(Identity.source == "github")
            )
        }
        repositories = {}
        for payload in snapshot.repositories:
            external_id = str(payload["id"])
            resource = self.session.scalar(
                select(Resource).where(
                    Resource.source == "github",
                    Resource.external_id == external_id,
                )
            )
            if resource is None:
                resource = Resource(
                    source="github",
                    external_id=external_id,
                    name=payload.get("full_name") or payload["name"],
                    resource_type=ResourceType.REPOSITORY,
                    sensitivity=Sensitivity.MODERATE if payload.get("private") else Sensitivity.LOW,
                )
                self.session.add(resource)
                self.session.flush()
            resource.source_metadata = {
                "organization": snapshot.organization,
                "visibility": payload.get("visibility"),
                "archived": bool(payload.get("archived", False)),
                "html_url": payload.get("html_url"),
            }
            repositories[payload["name"]] = resource
        active_external_ids = set()
        created = updated = 0
        for observed in snapshot.permissions:
            identity = identities[observed["login"]]
            resource = repositories[observed["repository"]]
            level = observed["permission"]
            permission = self.session.scalar(
                select(Permission).where(
                    Permission.resource_id == resource.id,
                    Permission.action == level,
                )
            )
            if permission is None:
                permission = Permission(
                    resource=resource,
                    action=level,
                    name=f"GitHub repository {level}",
                    privileged=level in {"admin", "maintain"},
                )
                self.session.add(permission)
                self.session.flush()
            external_id = f"{snapshot.organization}:{resource.external_id}:{identity.external_id}"
            active_external_ids.add(external_id)
            grant = self.session.scalar(
                select(AccessGrant).where(
                    AccessGrant.source == "github",
                    AccessGrant.external_id == external_id,
                )
            )
            if grant is None:
                grant = AccessGrant(
                    source="github",
                    external_id=external_id,
                    subject_type=GrantSubjectType.IDENTITY,
                    identity=identity,
                    permission=permission,
                    granted_at=datetime.now(UTC),
                )
                self.session.add(grant)
                created += 1
            else:
                grant.permission = permission
                grant.revoked_at = None
                updated += 1
            grant.business_reason = "Effective repository permission reported by GitHub"
            grant.policy_reference = "github-calculated-permission"
            grant.source_metadata = {
                "permission_source": observed["source"],
                "lineage_complete": False,
                "limitation": "GitHub reports the highest effective role across all grant sources",
            }
        revoked = 0
        for grant in self.session.scalars(
            select(AccessGrant).where(
                AccessGrant.source == "github",
                AccessGrant.revoked_at.is_(None),
            )
        ):
            if grant.external_id not in active_external_ids:
                grant.revoked_at = datetime.now(UTC)
                revoked += 1
        self.session.flush()
        for identity in identities.values():
            ProvenanceService(self.session).materialize_identity(identity)
        if checkpoint is None:
            checkpoint = ConnectorCheckpoint(
                connector="github",
                scope=snapshot.organization,
                fingerprint=snapshot.fingerprint,
                endpoint_cache={},
            )
            self.session.add(checkpoint)
        checkpoint.observed_at = datetime.now(UTC)
        checkpoint.fingerprint = snapshot.fingerprint
        checkpoint.endpoint_cache = snapshot.endpoint_cache
        self.session.add(
            AuditEvent(
                actor_type="connector",
                actor_id=f"github:{snapshot.organization}",
                action="github.authorization_snapshot.synchronized",
                entity_type="organization",
                entity_id=snapshot.organization,
                new_state={
                    "members": len(records),
                    "repositories": len(repositories),
                    "permissions": len(snapshot.permissions),
                    "grants_revoked": revoked,
                },
                reason="Read-only GitHub authorization evidence synchronization",
            )
        )
        self.session.commit()
        return GitHubSyncResult(
            len(records),
            len(repositories),
            len(snapshot.permissions),
            created,
            updated,
            revoked,
            snapshot.fingerprint,
            False,
        )
