from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import (
    AccessGrant,
    AuditEvent,
    GrantSubjectType,
    Identity,
    Permission,
    Resource,
    ResourceType,
    Role,
    Sensitivity,
)
from athena.services.provenance import ProvenanceService


class DemoScenarioError(RuntimeError):
    pass


class DemoScenarioService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def seed(self) -> dict[str, int]:
        alice = self._identity("alice")
        bob = self._identity("bob")
        developer = self.session.scalar(
            select(Role).where(Role.source == "keycloak", Role.name == "developer")
        )
        if developer is None:
            raise DemoScenarioError("Developer role is missing; synchronize Keycloak first")

        github = self._resource(
            "github",
            "GitHub",
            ResourceType.REPOSITORY,
            Sensitivity.MODERATE,
        )
        development_db = self._resource(
            "development-database",
            "Development Database",
            ResourceType.DATABASE,
            Sensitivity.MODERATE,
        )
        production_db = self._resource(
            "production-database",
            "Production Database",
            ResourceType.DATABASE,
            Sensitivity.CRITICAL,
        )
        github_write = self._permission(github, "write", "GitHub Repository Write", False)
        development_read = self._permission(
            development_db, "read", "Development Database Read", False
        )
        production_read = self._permission(
            production_db, "read", "Production Database Read", True
        )

        created = 0
        created += self._grant(
            "developer-github-write",
            GrantSubjectType.ROLE,
            github_write,
            role=developer,
            approved_by=bob,
            reason="Standard access for application developers",
            policy="POL-IAM-DEV-001",
        )
        created += self._grant(
            "developer-development-db-read",
            GrantSubjectType.ROLE,
            development_read,
            role=developer,
            approved_by=bob,
            reason="Development and testing responsibilities",
            policy="POL-IAM-DEV-002",
        )
        created += self._grant(
            "alice-production-db-read",
            GrantSubjectType.IDENTITY,
            production_read,
            identity=alice,
            approved_by=bob,
            reason=None,
            policy="POL-IAM-023",
        )

        entitlements = ProvenanceService(self.session).materialize_identity(alice)
        if created:
            self.session.add(
                AuditEvent(
                    actor_type="system",
                    actor_id="demo-scenario",
                    action="authorization_scenario.seeded",
                    entity_type="identity",
                    entity_id=str(alice.id),
                    new_state={"grants_created": created, "entitlements": len(entitlements)},
                    reason="Seed controlled authorization provenance ground truth",
                )
            )
        self.session.commit()
        return {"grants_created": created, "entitlements_materialized": len(entitlements)}

    def _identity(self, username: str) -> Identity:
        identity = self.session.scalar(select(Identity).where(Identity.username == username))
        if identity is None:
            raise DemoScenarioError(
                f"Identity {username} is missing; synchronize Keycloak first"
            )
        return identity

    def _resource(
        self,
        external_id: str,
        name: str,
        resource_type: ResourceType,
        sensitivity: Sensitivity,
    ) -> Resource:
        resource = self.session.scalar(
            select(Resource).where(
                Resource.source == "athena-demo", Resource.external_id == external_id
            )
        )
        if resource is None:
            resource = Resource(
                source="athena-demo",
                external_id=external_id,
                name=name,
                resource_type=resource_type,
                sensitivity=sensitivity,
            )
            self.session.add(resource)
            self.session.flush()
        return resource

    def _permission(
        self, resource: Resource, action: str, name: str, privileged: bool
    ) -> Permission:
        permission = self.session.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id, Permission.action == action
            )
        )
        if permission is None:
            permission = Permission(
                resource=resource,
                action=action,
                name=name,
                privileged=privileged,
            )
            self.session.add(permission)
            self.session.flush()
        return permission

    def _grant(
        self,
        external_id: str,
        subject_type: GrantSubjectType,
        permission: Permission,
        *,
        identity: Identity | None = None,
        role: Role | None = None,
        approved_by: Identity | None,
        reason: str | None,
        policy: str,
    ) -> int:
        existing = self.session.scalar(
            select(AccessGrant).where(
                AccessGrant.source == "athena-demo", AccessGrant.external_id == external_id
            )
        )
        if existing is not None:
            return 0
        self.session.add(
            AccessGrant(
                source="athena-demo",
                external_id=external_id,
                subject_type=subject_type,
                identity=identity,
                role=role,
                permission=permission,
                requested_by=identity,
                approved_by=approved_by,
                business_reason=reason,
                policy_reference=policy,
                granted_at=datetime.now(UTC),
            )
        )
        self.session.flush()
        return 1
