import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, Uuid


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


json_type = JSON().with_variant(JSONB(), "postgresql")


class IdentityType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    APPLICATION = "application"
    WORKLOAD = "workload"
    API_CLIENT = "api_client"
    AGENT = "agent"


class ResourceType(StrEnum):
    APPLICATION = "application"
    DATABASE = "database"
    CLOUD = "cloud"
    REPOSITORY = "repository"
    KUBERNETES = "kubernetes"
    DATA = "data"
    OTHER = "other"


class Sensitivity(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class GrantSubjectType(StrEnum):
    IDENTITY = "identity"
    GROUP = "group"
    ROLE = "role"


class PolicyDecision(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


identity_groups = Table(
    "identity_groups",
    Base.metadata,
    Column("identity_id", Uuid, ForeignKey("identities.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", Uuid, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


identity_roles = Table(
    "identity_roles",
    Base.metadata,
    Column("identity_id", Uuid, ForeignKey("identities.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class Identity(TimestampMixin, Base):
    __tablename__ = "identities"
    __table_args__ = (
        CheckConstraint(
            "identity_type IN "
            "('human', 'service_account', 'application', 'workload', 'api_client', 'agent')",
            name="ck_identities_identity_type",
        ),
        UniqueConstraint("source", "external_id", name="uq_identity_source_external"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    identity_type: Mapped[IdentityType] = mapped_column(
        Enum(
            IdentityType,
            name="identity_type",
            native_enum=False,
            create_constraint=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    department: Mapped[str | None] = mapped_column(String(128), index=True)
    job_title: Mapped[str | None] = mapped_column(String(255))
    manager_external_id: Mapped[str | None] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    groups: Mapped[list["Group"]] = relationship(
        secondary=identity_groups, back_populates="identities", lazy="selectin"
    )
    roles: Mapped[list["Role"]] = relationship(
        secondary=identity_roles, back_populates="identities", lazy="selectin"
    )


class Group(TimestampMixin, Base):
    __tablename__ = "groups"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_group_source_external"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    identities: Mapped[list[Identity]] = relationship(
        secondary=identity_groups, back_populates="groups"
    )


class Role(TimestampMixin, Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_role_source_external"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    identities: Mapped[list[Identity]] = relationship(
        secondary=identity_roles, back_populates="roles"
    )


class Resource(TimestampMixin, Base):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_resource_source_external"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[ResourceType] = mapped_column(
        Enum(
            ResourceType,
            name="resource_type",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(
            Sensitivity,
            name="resource_sensitivity",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    permissions: Mapped[list["Permission"]] = relationship(
        back_populates="resource", cascade="all, delete-orphan"
    )


class Permission(TimestampMixin, Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("resource_id", "action", name="uq_permission_resource_action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    resource_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("resources.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    resource: Mapped[Resource] = relationship(back_populates="permissions", lazy="joined")
    grants: Mapped[list["AccessGrant"]] = relationship(back_populates="permission")


class AccessGrant(TimestampMixin, Base):
    __tablename__ = "access_grants"
    __table_args__ = (
        CheckConstraint(
            "(CASE WHEN identity_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN group_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN role_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_access_grants_exactly_one_subject",
        ),
        UniqueConstraint("source", "external_id", name="uq_access_grant_source_external"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_type: Mapped[GrantSubjectType] = mapped_column(
        Enum(
            GrantSubjectType,
            name="grant_subject_type",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identities.id", ondelete="CASCADE")
    )
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("groups.id", ondelete="CASCADE")
    )
    role_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE")
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identities.id", ondelete="SET NULL")
    )
    approved_by_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identities.id", ondelete="SET NULL")
    )
    business_reason: Mapped[str | None] = mapped_column(Text)
    policy_reference: Mapped[str | None] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    permission: Mapped[Permission] = relationship(back_populates="grants", lazy="joined")
    identity: Mapped[Identity | None] = relationship(foreign_keys=[identity_id])
    group: Mapped[Group | None] = relationship(foreign_keys=[group_id])
    role: Mapped[Role | None] = relationship(foreign_keys=[role_id])
    requested_by: Mapped[Identity | None] = relationship(foreign_keys=[requested_by_identity_id])
    approved_by: Mapped[Identity | None] = relationship(foreign_keys=[approved_by_identity_id])


class EffectiveEntitlement(Base):
    __tablename__ = "effective_entitlements"
    __table_args__ = (
        UniqueConstraint("identity_id", "grant_id", name="uq_entitlement_identity_grant"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False
    )
    grant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("access_grants.id", ondelete="CASCADE"), nullable=False
    )
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    identity: Mapped[Identity] = relationship()
    permission: Mapped[Permission] = relationship(lazy="joined")
    grant: Mapped[AccessGrant] = relationship(lazy="joined")
    provenance_edges: Mapped[list["ProvenanceEdge"]] = relationship(
        back_populates="entitlement",
        cascade="all, delete-orphan",
        order_by="ProvenanceEdge.sequence",
        lazy="selectin",
    )


class ProvenanceEdge(Base):
    __tablename__ = "provenance_edges"
    __table_args__ = (
        UniqueConstraint("entitlement_id", "sequence", name="uq_provenance_edge_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("effective_entitlements.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    from_label: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship_type: Mapped[str] = mapped_column("relationship", String(64), nullable=False)
    to_type: Mapped[str] = mapped_column(String(64), nullable=False)
    to_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    to_label: Mapped[str] = mapped_column(String(255), nullable=False)

    entitlement: Mapped[EffectiveEntitlement] = relationship(back_populates="provenance_edges")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    old_state: Mapped[dict | None] = mapped_column(json_type)
    new_state: Mapped[dict | None] = mapped_column(json_type)
    policy_reference: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    approval: Mapped[dict | None] = mapped_column(json_type)
    risk_before: Mapped[float | None] = mapped_column(Float)
    risk_after: Mapped[float | None] = mapped_column(Float)
    model_version: Mapped[str | None] = mapped_column(String(255))


class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("effective_entitlements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    engine: Mapped[str] = mapped_column(String(64), nullable=False, default="opa")
    policy_path: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    decision: Mapped[PolicyDecision] = mapped_column(
        Enum(
            PolicyDecision,
            name="policy_decision",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    input_snapshot: Mapped[dict] = mapped_column(json_type, nullable=False)
    violations: Mapped[list] = mapped_column(json_type, nullable=False, default=list)

    entitlement: Mapped[EffectiveEntitlement] = relationship(lazy="joined")


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def prevent_audit_event_mutation(*_: object) -> None:
    raise ValueError("Audit events are append-only")


@event.listens_for(PolicyEvaluation, "before_update")
@event.listens_for(PolicyEvaluation, "before_delete")
def prevent_policy_evaluation_mutation(*_: object) -> None:
    raise ValueError("Policy evaluations are immutable")
