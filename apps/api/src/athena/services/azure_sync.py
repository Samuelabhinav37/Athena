import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.collectors.azure import AzureSnapshot
from athena.collectors.contracts import NormalizedGroup, NormalizedIdentity
from athena.models import (
    AccessGrant,
    AuditEvent,
    ConnectorCheckpoint,
    GrantSubjectType,
    Group,
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
class AzureSyncResult:
    identities: int
    groups: int
    role_assignments: int
    grants_created: int
    grants_updated: int
    grants_revoked: int
    fingerprint: str
    unchanged: bool


class AzureSyncService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def checkpoint(self, subscription_id: str) -> ConnectorCheckpoint | None:
        return self.session.scalar(
            select(ConnectorCheckpoint).where(
                ConnectorCheckpoint.connector == "azure_rbac",
                ConnectorCheckpoint.scope == subscription_id,
            )
        )

    def sync(self, snapshot: AzureSnapshot) -> AzureSyncResult:
        checkpoint = self.checkpoint(snapshot.subscription_id)
        if checkpoint is not None and checkpoint.fingerprint == snapshot.fingerprint:
            checkpoint.observed_at = datetime.now(UTC)
            checkpoint.endpoint_cache = snapshot.endpoint_cache
            self.session.commit()
            return self._result(snapshot, 0, 0, 0, True)

        group_records = {
            group["id"]: NormalizedGroup(
                external_id=group["id"],
                name=group.get("displayName") or group["id"],
                path=f"/tenants/{snapshot.tenant_id}/groups",
            )
            for group in snapshot.groups
        }
        memberships = {
            member_id: [
                group_records[group_id]
                for group_id, member_ids in snapshot.group_members.items()
                if member_id in member_ids and group_id in group_records
            ]
            for member_id in {
                member for members in snapshot.group_members.values() for member in members
            }
        }
        records = [
            NormalizedIdentity(
                source="azure_entra",
                external_id=user["id"],
                username=user.get("userPrincipalName") or user["id"],
                identity_type=IdentityType.HUMAN,
                display_name=user.get("displayName") or user.get("userPrincipalName") or user["id"],
                email=user.get("mail"),
                department=user.get("department"),
                job_title=user.get("jobTitle"),
                active=bool(user.get("accountEnabled", True)),
                source_metadata={"tenant_id": snapshot.tenant_id},
                groups=memberships.get(user["id"], []),
            )
            for user in snapshot.users
        ]
        records.extend(
            NormalizedIdentity(
                source="azure_entra",
                external_id=principal["id"],
                username=principal.get("appId") or principal["id"],
                identity_type=(
                    IdentityType.WORKLOAD
                    if principal.get("servicePrincipalType") == "ManagedIdentity"
                    else IdentityType.APPLICATION
                ),
                display_name=principal.get("displayName") or principal["id"],
                active=bool(principal.get("accountEnabled", True)),
                source_metadata={
                    "tenant_id": snapshot.tenant_id,
                    "application_id": principal.get("appId"),
                    "service_principal_type": principal.get("servicePrincipalType"),
                    "owner": self._owner(principal.get("AthenaOwners")),
                    "credential_expirations": self._credential_expirations(principal),
                },
                groups=memberships.get(principal["id"], []),
            )
            for principal in snapshot.service_principals
        )
        IdentitySyncService(self.session).sync(records)
        for group_record in group_records.values():
            existing = self.session.scalar(
                select(Group).where(
                    Group.source == "azure_entra",
                    Group.external_id == group_record.external_id,
                )
            )
            if existing is None:
                self.session.add(
                    Group(
                        source="azure_entra",
                        external_id=group_record.external_id,
                        name=group_record.name,
                        path=group_record.path,
                    )
                )
        active_identity_ids = {record.external_id for record in records}
        for identity in self.session.scalars(
            select(Identity).where(Identity.source == "azure_entra")
        ):
            if (
                identity.source_metadata.get("tenant_id") == snapshot.tenant_id
                and identity.external_id not in active_identity_ids
            ):
                identity.active = False
        self.session.flush()
        identities = {
            identity.external_id: identity
            for identity in self.session.scalars(
                select(Identity).where(Identity.source == "azure_entra")
            )
        }
        groups = {
            group.external_id: group
            for group in self.session.scalars(
                select(Group).where(Group.source == "azure_entra")
            )
        }
        definitions = {item["id"].lower(): item for item in snapshot.role_definitions}
        active_grant_ids: set[str] = set()
        created = updated = 0
        for assignment in snapshot.role_assignments:
            properties = assignment.get("properties", {})
            principal_id = properties.get("principalId")
            role_id = str(properties.get("roleDefinitionId", "")).lower()
            definition = definitions.get(role_id)
            if not principal_id or definition is None:
                continue
            subject = self._subject(principal_id, identities, groups)
            if subject is None:
                continue
            role_properties = definition.get("properties", {})
            actions = self._actions(role_properties)
            for action in actions:
                resource = self._resource(snapshot.subscription_id, properties.get("scope", "/"))
                permission = self._permission(
                    resource, action, role_properties.get("roleName", "Azure role")
                )
                external_id = hashlib.sha256(f"{assignment['id']}:{action}".encode()).hexdigest()
                active_grant_ids.add(external_id)
                grant = self.session.scalar(
                    select(AccessGrant).where(
                        AccessGrant.source == "azure_rbac",
                        AccessGrant.external_id == external_id,
                    )
                )
                if grant is None:
                    grant = AccessGrant(
                        source="azure_rbac",
                        external_id=external_id,
                        subject_type=subject[0],
                        permission=permission,
                        granted_at=datetime.now(UTC),
                    )
                    self.session.add(grant)
                    created += 1
                else:
                    grant.permission = permission
                    grant.revoked_at = None
                    updated += 1
                if subject[0] == GrantSubjectType.IDENTITY:
                    grant.identity = subject[1]
                    grant.group = None
                else:
                    grant.group = subject[1]
                    grant.identity = None
                grant.business_reason = "Observed Azure RBAC role assignment"
                grant.policy_reference = role_id[:255]
                grant.source_metadata = {
                    "subscription_id": snapshot.subscription_id,
                    "role_definition_name": role_properties.get("roleName"),
                    "assignment_scope": properties.get("scope"),
                    "condition": properties.get("condition"),
                    "lineage_complete": False,
                    "limitation": (
                        "Inventory does not resolve deny assignments, management-group "
                        "inheritance, PIM activation, or resource-specific data-plane authorization"
                    ),
                }
        revoked = 0
        for grant in self.session.scalars(
            select(AccessGrant).where(
                AccessGrant.source == "azure_rbac", AccessGrant.revoked_at.is_(None)
            )
        ):
            if (
                grant.source_metadata.get("subscription_id") == snapshot.subscription_id
                and grant.external_id not in active_grant_ids
            ):
                grant.revoked_at = datetime.now(UTC)
                revoked += 1
        self.session.flush()
        for identity in identities.values():
            ProvenanceService(self.session).materialize_identity(identity)
        if checkpoint is None:
            checkpoint = ConnectorCheckpoint(
                connector="azure_rbac",
                scope=snapshot.subscription_id,
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
                actor_id=f"azure:{snapshot.tenant_id}",
                action="azure_rbac.authorization_snapshot.synchronized",
                entity_type="azure_subscription",
                entity_id=snapshot.subscription_id,
                new_state={
                    "identities": len(records),
                    "groups": len(snapshot.groups),
                    "role_assignments": len(snapshot.role_assignments),
                    "grants_revoked": revoked,
                },
                reason="Read-only Microsoft Entra and Azure RBAC evidence synchronization",
            )
        )
        self.session.commit()
        return self._result(snapshot, created, updated, revoked, False)

    @staticmethod
    def _owner(owners: object) -> str | None:
        if not isinstance(owners, list) or not owners:
            return None
        candidates = sorted(
            owner.get("userPrincipalName") or owner.get("displayName")
            for owner in owners
            if isinstance(owner, dict)
            and (owner.get("userPrincipalName") or owner.get("displayName"))
        )
        return candidates[0] if candidates else None

    @staticmethod
    def _credential_expirations(principal: dict) -> list[str]:
        values = []
        for credential in principal.get("passwordCredentials", []) + principal.get(
            "keyCredentials", []
        ):
            if isinstance(credential, dict) and isinstance(credential.get("endDateTime"), str):
                values.append(credential["endDateTime"])
        return sorted(set(values))

    @staticmethod
    def _actions(properties: dict) -> list[str]:
        actions = []
        for permission in properties.get("permissions", []):
            if isinstance(permission, dict):
                actions.extend(
                    item for item in permission.get("actions", []) if isinstance(item, str)
                )
                actions.extend(
                    item for item in permission.get("dataActions", []) if isinstance(item, str)
                )
        return sorted(set(actions))

    @staticmethod
    def _subject(principal_id: str, identities: dict, groups: dict) -> tuple | None:
        if principal_id in identities:
            return GrantSubjectType.IDENTITY, identities[principal_id]
        if principal_id in groups:
            return GrantSubjectType.GROUP, groups[principal_id]
        return None

    def _resource(self, subscription_id: str, scope: str) -> Resource:
        external_id = hashlib.sha256(f"{subscription_id}:{scope}".encode()).hexdigest()
        resource = self.session.scalar(
            select(Resource).where(
                Resource.source == "azure_rbac", Resource.external_id == external_id
            )
        )
        if resource is None:
            resource = Resource(
                source="azure_rbac",
                external_id=external_id,
                name=scope[:255],
                resource_type=ResourceType.CLOUD,
                sensitivity=Sensitivity.HIGH if scope.count("/") <= 2 else Sensitivity.MODERATE,
                source_metadata={"subscription_id": subscription_id, "scope": scope},
            )
            self.session.add(resource)
            self.session.flush()
        return resource

    def _permission(self, resource: Resource, action: str, role_name: str) -> Permission:
        permission = self.session.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id, Permission.action == action
            )
        )
        if permission is None:
            permission = Permission(
                resource=resource,
                action=action,
                name=f"Azure {role_name}: {action}"[:255],
                privileged=(
                    action == "*"
                    or action.lower().startswith("microsoft.authorization/")
                ),
            )
            self.session.add(permission)
            self.session.flush()
        return permission

    @staticmethod
    def _result(
        snapshot: AzureSnapshot,
        created: int,
        updated: int,
        revoked: int,
        unchanged: bool,
    ) -> AzureSyncResult:
        return AzureSyncResult(
            len(snapshot.users) + len(snapshot.service_principals),
            len(snapshot.groups),
            len(snapshot.role_assignments),
            created,
            updated,
            revoked,
            snapshot.fingerprint,
            unchanged,
        )
