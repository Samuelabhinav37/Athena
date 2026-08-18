import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.collectors.aws_iam import AwsIamSnapshot
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
class AwsIamSyncResult:
    identities: int
    groups: int
    policies: int
    allowed_statements: int
    grants_created: int
    grants_updated: int
    grants_revoked: int
    fingerprint: str
    unchanged: bool


class AwsIamSyncService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def checkpoint(self, account_id: str) -> ConnectorCheckpoint | None:
        return self.session.scalar(
            select(ConnectorCheckpoint).where(
                ConnectorCheckpoint.connector == "aws_iam",
                ConnectorCheckpoint.scope == account_id,
            )
        )

    def sync(self, snapshot: AwsIamSnapshot) -> AwsIamSyncResult:
        checkpoint = self.checkpoint(snapshot.account_id)
        if checkpoint is not None and checkpoint.fingerprint == snapshot.fingerprint:
            checkpoint.observed_at = datetime.now(UTC)
            checkpoint.endpoint_cache = snapshot.endpoint_cache
            self.session.commit()
            return self._result(snapshot, 0, 0, 0, True)

        groups_by_name = {
            group["GroupName"]: NormalizedGroup(
                external_id=group["GroupId"],
                name=group["GroupName"],
                path=group.get("Path", "/"),
            )
            for group in snapshot.groups
        }
        records = [
            NormalizedIdentity(
                source="aws_iam",
                external_id=user["UserId"],
                username=user["UserName"],
                identity_type=IdentityType.HUMAN,
                display_name=user["UserName"],
                active=True,
                source_metadata={
                    "account_id": snapshot.account_id,
                    "arn": user["Arn"],
                    "path": user.get("Path", "/"),
                    "access_keys": self._key_metadata(user["UserName"], snapshot.access_keys),
                    "permissions_boundary": user.get("PermissionsBoundary"),
                },
                groups=[groups_by_name[name] for name in user.get("GroupList", [])],
            )
            for user in snapshot.users
        ]
        records.extend(
            NormalizedIdentity(
                source="aws_iam",
                external_id=role["RoleId"],
                username=role["RoleName"],
                identity_type=IdentityType.SERVICE_ACCOUNT,
                display_name=role["RoleName"],
                active=True,
                source_metadata={
                    "account_id": snapshot.account_id,
                    "arn": role["Arn"],
                    "path": role.get("Path", "/"),
                    "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                    "permissions_boundary": role.get("PermissionsBoundary"),
                    "owner": role.get("AthenaPosture", {}).get("Owner"),
                    "role_last_used_at": self._isoformat(
                        role.get("AthenaPosture", {}).get("LastUsedAt")
                    ),
                    "role_last_used_region": role.get("AthenaPosture", {}).get(
                        "LastUsedRegion"
                    ),
                },
            )
            for role in snapshot.roles
        )
        IdentitySyncService(self.session).sync(records)
        active_identity_ids = {record.external_id for record in records}
        for identity in self.session.scalars(
            select(Identity).where(Identity.source == "aws_iam")
        ):
            if (
                identity.source_metadata.get("account_id") == snapshot.account_id
                and identity.external_id not in active_identity_ids
            ):
                identity.active = False
        identities = {
            identity.external_id: identity
            for identity in self.session.scalars(
                select(Identity).where(Identity.source == "aws_iam")
            )
        }
        groups = {
            group.external_id: group
            for group in self.session.scalars(select(Group).where(Group.source == "aws_iam"))
        }

        managed = self._managed_policy_documents(snapshot.policies)
        observations = []
        for user in snapshot.users:
            observations.extend(self._principal_policies("identity", user, managed))
        for role in snapshot.roles:
            observations.extend(self._principal_policies("identity", role, managed))
        for group in snapshot.groups:
            observations.extend(self._principal_policies("group", group, managed))

        active_external_ids = set()
        created = updated = 0
        for observation in observations:
            resource = self._resource(snapshot.account_id, observation["resource"])
            permission = self._permission(resource, observation["action"])
            subject = self._subject(observation, identities, groups)
            grant_key = ":".join(
                [
                    snapshot.account_id,
                    observation["subject_type"],
                    observation["subject_id"],
                    observation["policy_id"],
                    observation["statement_id"],
                    observation["action"],
                    observation["resource"],
                ]
            )
            external_id = hashlib.sha256(grant_key.encode()).hexdigest()
            active_external_ids.add(external_id)
            grant = self.session.scalar(
                select(AccessGrant).where(
                    AccessGrant.source == "aws_iam", AccessGrant.external_id == external_id
                )
            )
            if grant is None:
                grant = AccessGrant(
                    source="aws_iam",
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
            grant.business_reason = "Observed Allow statement in AWS IAM policy inventory"
            grant.policy_reference = observation["policy_id"][:255]
            grant.source_metadata = {
                "policy_name": observation["policy_name"],
                "statement_id": observation["statement_id"],
                "condition": observation["condition"],
                "lineage_complete": False,
                "limitation": (
                    "Inventory does not resolve explicit deny, permissions boundaries, SCPs, "
                    "resource policies, or session policies"
                ),
            }

        revoked = 0
        for grant in self.session.scalars(
            select(AccessGrant).where(
                AccessGrant.source == "aws_iam", AccessGrant.revoked_at.is_(None)
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
                connector="aws_iam",
                scope=snapshot.account_id,
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
                actor_id=f"aws:{snapshot.account_id}",
                action="aws_iam.authorization_snapshot.synchronized",
                entity_type="aws_account",
                entity_id=snapshot.account_id,
                new_state={
                    "identities": len(records),
                    "groups": len(snapshot.groups),
                    "policies": len(snapshot.policies),
                    "allowed_statements": len(observations),
                    "grants_revoked": revoked,
                },
                reason="Read-only AWS IAM authorization evidence synchronization",
            )
        )
        self.session.commit()
        return self._result(snapshot, created, updated, revoked, False, len(observations))

    @staticmethod
    def _key_metadata(username: str, keys: list[dict]) -> list[dict]:
        metadata = []
        for key in keys:
            if key["UserName"] != username:
                continue
            created_at = key["CreateDate"]
            metadata.append({
                "status": key["Status"],
                "created_at": created_at.isoformat()
                if hasattr(created_at, "isoformat")
                else str(created_at),
                "age_days": key.get("AgeDays"),
            })
        return metadata

    @staticmethod
    def _isoformat(value: object) -> str | None:
        if value is None:
            return None
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    @staticmethod
    def _managed_policy_documents(policies: list[dict]) -> dict[str, dict]:
        result = {}
        for policy in policies:
            default = next(
                (
                    version
                    for version in policy.get("PolicyVersionList", [])
                    if version.get("IsDefaultVersion")
                ),
                None,
            )
            if default:
                result[policy["Arn"]] = default.get("Document", {})
        return result

    def _principal_policies(
        self, subject_type: str, principal: dict, managed: dict[str, dict]
    ) -> list[dict]:
        subject_id = principal.get("UserId") or principal.get("RoleId") or principal["GroupId"]
        prefix = "User" if "UserId" in principal else "Role" if "RoleId" in principal else "Group"
        policies = [
            (
                item["PolicyName"],
                f"inline:{prefix}:{subject_id}:{item['PolicyName']}",
                item["PolicyDocument"],
            )
            for item in principal.get(f"{prefix}PolicyList", [])
        ]
        policies.extend(
            (item["PolicyName"], item["PolicyArn"], managed.get(item["PolicyArn"], {}))
            for item in principal.get("AttachedManagedPolicies", [])
        )
        observations = []
        for policy_name, policy_id, document in policies:
            statements = document.get("Statement", []) if isinstance(document, dict) else []
            if isinstance(statements, dict):
                statements = [statements]
            for index, statement in enumerate(statements):
                if statement.get("Effect") != "Allow":
                    continue
                actions = statement.get("Action", [])
                resources = statement.get("Resource", "*")
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                for action in actions:
                    for resource in resources:
                        observations.append(
                            {
                                "subject_type": subject_type,
                                "subject_id": subject_id,
                                "policy_name": policy_name,
                                "policy_id": policy_id,
                                "statement_id": str(statement.get("Sid", index)),
                                "action": action,
                                "resource": resource,
                                "condition": statement.get("Condition", {}),
                            }
                        )
        return observations

    def _resource(self, account_id: str, arn: str) -> Resource:
        resource_key = f"{account_id}:{arn}"
        external_id = hashlib.sha256(resource_key.encode()).hexdigest()
        resource = self.session.scalar(
            select(Resource).where(
                Resource.source == "aws_iam", Resource.external_id == external_id
            )
        )
        if resource is None:
            resource = Resource(
                source="aws_iam",
                external_id=external_id,
                name=arn[:255],
                resource_type=ResourceType.CLOUD,
                sensitivity=Sensitivity.HIGH if arn == "*" else Sensitivity.MODERATE,
                source_metadata={"account_id": account_id, "resource_pattern": arn},
            )
            self.session.add(resource)
            self.session.flush()
        return resource

    def _permission(self, resource: Resource, action: str) -> Permission:
        permission = self.session.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id, Permission.action == action
            )
        )
        if permission is None:
            permission = Permission(
                resource=resource,
                action=action,
                name=f"AWS {action}",
                privileged=action == "*" or action.lower().startswith("iam:"),
            )
            self.session.add(permission)
            self.session.flush()
        return permission

    @staticmethod
    def _subject(observation: dict, identities: dict, groups: dict) -> tuple:
        if observation["subject_type"] == "identity":
            return GrantSubjectType.IDENTITY, identities[observation["subject_id"]]
        return GrantSubjectType.GROUP, groups[observation["subject_id"]]

    @staticmethod
    def _result(
        snapshot: AwsIamSnapshot,
        created: int,
        updated: int,
        revoked: int,
        unchanged: bool,
        allowed_statements: int | None = None,
    ) -> AwsIamSyncResult:
        return AwsIamSyncResult(
            len(snapshot.users) + len(snapshot.roles),
            len(snapshot.groups),
            len(snapshot.policies),
            allowed_statements if allowed_statements is not None else 0,
            created,
            updated,
            revoked,
            snapshot.fingerprint,
            unchanged,
        )
