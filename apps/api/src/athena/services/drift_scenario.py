from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import (
    AccessObservation,
    AuditEvent,
    EffectiveEntitlement,
    Identity,
    Role,
    RoleTransition,
)
from athena.services.demo_scenario import DemoScenarioError


class DriftScenarioService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def apply(self) -> dict[str, int]:
        alice = self._identity("alice")
        security_role = self.session.scalar(
            select(Role).where(Role.source == "keycloak", Role.name == "security-analyst")
        )
        if security_role is None:
            raise DemoScenarioError("Security Analyst role is missing; synchronize Keycloak first")

        transition = self.session.scalar(
            select(RoleTransition).where(RoleTransition.identity_id == alice.id)
        )
        transitions_created = 0
        if transition is None:
            now = datetime.now(UTC)
            from_roles = sorted(role.name for role in alice.roles)
            alice.department = "security"
            alice.job_title = "Security Analyst"
            alice.roles = [
                role for role in alice.roles if role.name != "developer"
            ] + [security_role]
            transition = RoleTransition(
                identity=alice,
                from_department="engineering",
                to_department="security",
                from_roles=from_roles,
                to_roles=sorted(role.name for role in alice.roles),
                effective_at=now,
                actor_type="system",
                actor_id="drift-demo",
                reason="Controlled transfer from Engineering to Security",
            )
            self.session.add(transition)
            self.session.add(
                AuditEvent(
                    actor_type="system",
                    actor_id="drift-demo",
                    action="identity.role_transition.recorded",
                    entity_type="identity",
                    entity_id=str(alice.id),
                    old_state={"department": "engineering", "roles": from_roles},
                    new_state={
                        "department": "security",
                        "roles": sorted(role.name for role in alice.roles),
                    },
                    reason=transition.reason,
                )
            )
            transitions_created = 1
            self.session.flush()

        entitlements = list(
            self.session.scalars(
                select(EffectiveEntitlement).where(
                    EffectiveEntitlement.identity_id == alice.id,
                    EffectiveEntitlement.active.is_(True),
                )
            )
        )
        activity_days = {
            "github": 60,
            "development-database": 45,
            "production-database": 120,
        }
        observations_created = 0
        now = datetime.now(UTC)
        for entitlement in entitlements:
            resource_key = entitlement.permission.resource.external_id
            days = activity_days.get(resource_key, 30)
            external_id = f"alice-{resource_key}-activity-v1"
            observation = self.session.scalar(
                select(AccessObservation).where(
                    AccessObservation.source == "athena-demo",
                    AccessObservation.external_id == external_id,
                )
            )
            if observation is None:
                observation = AccessObservation(
                    entitlement=entitlement,
                    source="athena-demo",
                    external_id=external_id,
                    last_used_at=now - timedelta(days=days),
                    usage_count=0 if days >= 90 else 2,
                    source_metadata={"scenario": "alice-role-drift"},
                )
                self.session.add(observation)
                observations_created += 1
        self.session.commit()
        return {
            "transitions_created": transitions_created,
            "observations_created": observations_created,
            "retained_entitlements": len(entitlements),
        }

    def _identity(self, username: str) -> Identity:
        identity = self.session.scalar(select(Identity).where(Identity.username == username))
        if identity is None:
            raise DemoScenarioError(
                f"Identity {username} is missing; synchronize Keycloak first"
            )
        return identity
