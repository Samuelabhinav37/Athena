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
    ForeignKeyConstraint,
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


def tenant_foreign_key(
    column: str, parent: str, name: str, *, ondelete: str
) -> ForeignKeyConstraint:
    return ForeignKeyConstraint(
        ["tenant_id", column],
        [f"{parent}.tenant_id", f"{parent}.id"],
        name=name,
        ondelete=ondelete,
    )


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


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFindingType(StrEnum):
    RETAINED_ACCESS = "retained_access"
    PEER_DEVIATION = "peer_deviation"
    STALE_ACCESS = "stale_access"
    POLICY_VIOLATION = "policy_violation"


class ReviewStatus(StrEnum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    CANCELLED = "cancelled"


class ReviewDecision(StrEnum):
    RETAIN = "retain"
    REVOKE = "revoke"
    EXTEND = "extend"
    EXCEPTION = "exception"


class MonitoringStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"


identity_groups = Table(
    "identity_groups",
    Base.metadata,
    Column("tenant_id", String(63), ForeignKey("tenants.id"), nullable=False, index=True),
    Column("identity_id", Uuid, primary_key=True),
    Column("group_id", Uuid, primary_key=True),
    ForeignKeyConstraint(
        ["tenant_id", "identity_id"],
        ["identities.tenant_id", "identities.id"],
        name="fk_identity_groups_tenant_identity_id_identities",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "group_id"],
        ["groups.tenant_id", "groups.id"],
        name="fk_identity_groups_tenant_group_id_groups",
        ondelete="CASCADE",
    ),
)


identity_roles = Table(
    "identity_roles",
    Base.metadata,
    Column("tenant_id", String(63), ForeignKey("tenants.id"), nullable=False, index=True),
    Column("identity_id", Uuid, primary_key=True),
    Column("role_id", Uuid, primary_key=True),
    ForeignKeyConstraint(
        ["tenant_id", "identity_id"],
        ["identities.tenant_id", "identities.id"],
        name="fk_identity_roles_tenant_identity_id_identities",
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["tenant_id", "role_id"],
        ["roles.tenant_id", "roles.id"],
        name="fk_identity_roles_tenant_role_id_roles",
        ondelete="CASCADE",
    ),
)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class TenantScopedMixin:
    tenant_id: Mapped[str] = mapped_column(
        String(63), ForeignKey("tenants.id"), nullable=False, index=True
    )


class Tenant(TimestampMixin, Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(63), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    approval_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    inventory_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class Identity(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "identities"
    __table_args__ = (
        CheckConstraint(
            "identity_type IN "
            "('human', 'service_account', 'application', 'workload', 'api_client', 'agent')",
            name="ck_identities_identity_type",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_identities_tenant_id"),
        UniqueConstraint(
            "tenant_id", "source", "external_id", name="uq_identities_tenant_source_external_id"
        ),
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


class Group(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "groups"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_groups_tenant_id"),
        UniqueConstraint(
            "tenant_id", "source", "external_id", name="uq_groups_tenant_source_external_id"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    identities: Mapped[list[Identity]] = relationship(
        secondary=identity_groups, back_populates="groups"
    )


class Role(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_roles_tenant_id"),
        UniqueConstraint(
            "tenant_id", "source", "external_id", name="uq_roles_tenant_source_external_id"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    identities: Mapped[list[Identity]] = relationship(
        secondary=identity_roles, back_populates="roles"
    )


class Resource(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_resources_tenant_id"),
        UniqueConstraint(
            "tenant_id", "source", "external_id", name="uq_resources_tenant_source_external_id"
        ),
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


class Permission(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_permissions_tenant_id"),
        UniqueConstraint(
            "tenant_id", "resource_id", "action", name="uq_permissions_tenant_resource_id_action"
        ),
        tenant_foreign_key(
            "resource_id",
            "resources",
            "fk_permissions_tenant_resource_id_resources",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    resource_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    resource: Mapped[Resource] = relationship(back_populates="permissions", lazy="joined")
    grants: Mapped[list["AccessGrant"]] = relationship(back_populates="permission")


class AccessGrant(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "access_grants"
    __table_args__ = (
        CheckConstraint(
            "(CASE WHEN identity_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN group_id IS NOT NULL THEN 1 ELSE 0 END + "
            "CASE WHEN role_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_access_grants_exactly_one_subject",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_access_grants_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "source",
            "external_id",
            name="uq_access_grants_tenant_source_external_id",
        ),
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_access_grants_tenant_identity_id_identities",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "group_id", "groups", "fk_access_grants_tenant_group_id_groups", ondelete="CASCADE"
        ),
        tenant_foreign_key(
            "role_id", "roles", "fk_access_grants_tenant_role_id_roles", ondelete="CASCADE"
        ),
        tenant_foreign_key(
            "permission_id",
            "permissions",
            "fk_access_grants_tenant_permission_id_permissions",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "requested_by_identity_id",
            "identities",
            "fk_access_grants_tenant_requested_by_identity_id_identities",
            ondelete="RESTRICT",
        ),
        tenant_foreign_key(
            "approved_by_identity_id",
            "identities",
            "fk_access_grants_tenant_approved_by_identity_id_identities",
            ondelete="RESTRICT",
        ),
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
    identity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    group_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    role_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    permission_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    requested_by_identity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approved_by_identity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    business_reason: Mapped[str | None] = mapped_column(Text)
    policy_reference: Mapped[str | None] = mapped_column(String(255))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    permission: Mapped[Permission] = relationship(back_populates="grants", lazy="joined")
    identity: Mapped[Identity | None] = relationship(foreign_keys=[identity_id])
    group: Mapped[Group | None] = relationship(foreign_keys=[group_id])
    role: Mapped[Role | None] = relationship(foreign_keys=[role_id])
    requested_by: Mapped[Identity | None] = relationship(foreign_keys=[requested_by_identity_id])
    approved_by: Mapped[Identity | None] = relationship(foreign_keys=[approved_by_identity_id])


class EffectiveEntitlement(TenantScopedMixin, Base):
    __tablename__ = "effective_entitlements"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_effective_entitlements_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "identity_id",
            "grant_id",
            name="uq_effective_entitlements_tenant_identity_id_grant_id",
        ),
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_effective_entitlements_tenant_identity_id_identities",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "permission_id",
            "permissions",
            "fk_effective_entitlements_tenant_permission_id_permissions",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "grant_id",
            "access_grants",
            "fk_effective_entitlements_tenant_grant_id_access_grants",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    grant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    identity: Mapped[Identity] = relationship()
    permission: Mapped[Permission] = relationship(lazy="joined", overlaps="identity")
    grant: Mapped[AccessGrant] = relationship(lazy="joined", overlaps="identity,permission")
    provenance_edges: Mapped[list["ProvenanceEdge"]] = relationship(
        back_populates="entitlement",
        cascade="all, delete-orphan",
        order_by="ProvenanceEdge.sequence",
        lazy="selectin",
    )


class ProvenanceEdge(TenantScopedMixin, Base):
    __tablename__ = "provenance_edges"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "entitlement_id",
            "sequence",
            name="uq_provenance_edges_tenant_entitlement_id_sequence",
        ),
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_provenance_edges_tenant_entitlement_id_effective_en_e5c909d5",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    from_label: Mapped[str] = mapped_column(String(255), nullable=False)
    relationship_type: Mapped[str] = mapped_column("relationship", String(64), nullable=False)
    to_type: Mapped[str] = mapped_column(String(64), nullable=False)
    to_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    to_label: Mapped[str] = mapped_column(String(255), nullable=False)

    entitlement: Mapped[EffectiveEntitlement] = relationship(back_populates="provenance_edges")


class AuditEvent(TenantScopedMixin, Base):
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


class PolicyEvaluation(TenantScopedMixin, Base):
    __tablename__ = "policy_evaluations"

    __table_args__ = (
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_policy_evaluations_tenant_entitlement_id_effective__a53ac551",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
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


class RoleTransition(TenantScopedMixin, Base):
    __tablename__ = "role_transitions"

    __table_args__ = (
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_role_transitions_tenant_identity_id_identities",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    from_department: Mapped[str | None] = mapped_column(String(128))
    to_department: Mapped[str | None] = mapped_column(String(128))
    from_roles: Mapped[list] = mapped_column(json_type, nullable=False)
    to_roles: Mapped[list] = mapped_column(json_type, nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    identity: Mapped[Identity] = relationship()


class AccessObservation(TenantScopedMixin, Base):
    __tablename__ = "access_observations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "source",
            "external_id",
            name="uq_access_observations_tenant_source_external_id",
        ),
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_access_observations_tenant_entitlement_id_effective_cc0bf557",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_metadata: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    entitlement: Mapped[EffectiveEntitlement] = relationship()


class RiskAssessment(TenantScopedMixin, Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_assessment_score_range"),
        UniqueConstraint("tenant_id", "id", name="uq_risk_assessments_tenant_id"),
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_risk_assessments_tenant_identity_id_identities",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[RiskLevel] = mapped_column(
        Enum(
            RiskLevel,
            name="risk_level",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    peer_definition: Mapped[dict] = mapped_column(json_type, nullable=False)
    summary: Mapped[dict] = mapped_column(json_type, nullable=False)

    identity: Mapped[Identity] = relationship()
    findings: Mapped[list["RiskFinding"]] = relationship(
        back_populates="assessment",
        cascade="all, delete-orphan",
        order_by="RiskFinding.score.desc()",
        lazy="selectin",
    )


class RiskFinding(TenantScopedMixin, Base):
    __tablename__ = "risk_findings"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_finding_score_range"),
        tenant_foreign_key(
            "assessment_id",
            "risk_assessments",
            "fk_risk_findings_tenant_assessment_id_risk_assessments",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_risk_findings_tenant_entitlement_id_effective_entitlements",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    assessment_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    finding_type: Mapped[RiskFindingType] = mapped_column(
        Enum(
            RiskFindingType,
            name="risk_finding_type",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    factors: Mapped[dict] = mapped_column(json_type, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    assessment: Mapped[RiskAssessment] = relationship(back_populates="findings")
    entitlement: Mapped[EffectiveEntitlement] = relationship(
        lazy="joined", overlaps="assessment,findings"
    )


class AnomalyModelRun(TenantScopedMixin, Base):
    __tablename__ = "anomaly_model_runs"

    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_anomaly_model_runs_tenant_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    library_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    random_seed: Mapped[int] = mapped_column(Integer, nullable=False)
    contamination: Mapped[float] = mapped_column(Float, nullable=False)
    feature_schema: Mapped[list] = mapped_column(json_type, nullable=False)
    training_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)
    peer_definition: Mapped[dict] = mapped_column(json_type, nullable=False)
    summary: Mapped[dict] = mapped_column(json_type, nullable=False)

    results: Mapped[list["AnomalyResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )


class AnomalyResult(TenantScopedMixin, Base):
    __tablename__ = "anomaly_results"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_anomaly_results_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "run_id",
            "subject_key",
            name="uq_anomaly_results_tenant_run_id_subject_key",
        ),
        tenant_foreign_key(
            "run_id",
            "anomaly_model_runs",
            "fk_anomaly_results_tenant_run_id_anomaly_model_runs",
            ondelete="CASCADE",
        ),
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_anomaly_results_tenant_identity_id_identities",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    subject_key: Mapped[str] = mapped_column(String(255), nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False)
    score_samples: Mapped[float] = mapped_column(Float, nullable=False)
    decision_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False)
    features: Mapped[dict] = mapped_column(json_type, nullable=False)
    explanation: Mapped[dict] = mapped_column(json_type, nullable=False)

    run: Mapped[AnomalyModelRun] = relationship(back_populates="results")
    identity: Mapped[Identity | None] = relationship(overlaps="results,run")


class ReviewCase(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "review_cases"
    __table_args__ = (
        CheckConstraint(
            "risk_assessment_id IS NOT NULL OR anomaly_result_id IS NOT NULL",
            name="ck_review_case_has_evidence",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_review_cases_tenant_id"),
        tenant_foreign_key(
            "identity_id",
            "identities",
            "fk_review_cases_tenant_identity_id_identities",
            ondelete="RESTRICT",
        ),
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_review_cases_tenant_entitlement_id_effective_entitlements",
            ondelete="RESTRICT",
        ),
        tenant_foreign_key(
            "risk_assessment_id",
            "risk_assessments",
            "fk_review_cases_tenant_risk_assessment_id_risk_assessments",
            ondelete="RESTRICT",
        ),
        tenant_foreign_key(
            "anomaly_result_id",
            "anomaly_results",
            "fk_review_cases_tenant_anomaly_result_id_anomaly_results",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    identity_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    entitlement_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    anomaly_result_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ReviewStatus] = mapped_column(
        Enum(
            ReviewStatus,
            name="review_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
        default=ReviewStatus.OPEN,
    )
    owner: Mapped[str | None] = mapped_column(String(255), index=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    resolution: Mapped[ReviewDecision | None] = mapped_column(
        Enum(
            ReviewDecision,
            name="review_decision",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        )
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    identity: Mapped[Identity] = relationship()
    events: Mapped[list["ReviewEvent"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="ReviewEvent.occurred_at",
        lazy="selectin",
    )


class ReviewEvent(TenantScopedMixin, Base):
    __tablename__ = "review_events"

    __table_args__ = (
        tenant_foreign_key(
            "case_id",
            "review_cases",
            "fk_review_events_tenant_case_id_review_cases",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[ReviewStatus | None] = mapped_column(
        Enum(
            ReviewStatus,
            name="review_event_from_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        )
    )
    to_status: Mapped[ReviewStatus] = mapped_column(
        Enum(
            ReviewStatus,
            name="review_event_to_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    decision: Mapped[ReviewDecision | None] = mapped_column(
        Enum(
            ReviewDecision,
            name="review_event_decision",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        )
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_snapshot: Mapped[dict] = mapped_column(json_type, nullable=False)
    execution_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_executed"
    )

    case: Mapped[ReviewCase] = relationship(back_populates="events")


class RemediationExecution(TenantScopedMixin, TimestampMixin, Base):
    __tablename__ = "remediation_executions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_remediation_executions_tenant_id"),
        UniqueConstraint("tenant_id", "case_id", name="uq_remediation_executions_tenant_case_id"),
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_remediation_executions_tenant_idempotency_key",
        ),
        tenant_foreign_key(
            "case_id",
            "review_cases",
            "fk_remediation_executions_tenant_case_id_review_cases",
            ondelete="RESTRICT",
        ),
        tenant_foreign_key(
            "entitlement_id",
            "effective_entitlements",
            "fk_remediation_executions_tenant_entitlement_id_effect_3119a53f",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    entitlement_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    target_external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ExecutionStatus] = mapped_column(
        Enum(
            ExecutionStatus,
            name="remediation_execution_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
        default=ExecutionStatus.PENDING,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    before_evidence: Mapped[dict] = mapped_column(json_type, nullable=False)
    after_evidence: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)
    adapter_receipt: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    case: Mapped[ReviewCase] = relationship()
    entitlement: Mapped[EffectiveEntitlement] = relationship(overlaps="case")
    events: Mapped[list["RemediationExecutionEvent"]] = relationship(
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="RemediationExecutionEvent.occurred_at",
        lazy="selectin",
    )


class RemediationExecutionEvent(TenantScopedMixin, Base):
    __tablename__ = "remediation_execution_events"

    __table_args__ = (
        tenant_foreign_key(
            "execution_id",
            "remediation_executions",
            "fk_remediation_execution_events_tenant_execution_id_re_c6ee28cc",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    execution_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        nullable=False,
        index=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[ExecutionStatus | None] = mapped_column(
        Enum(
            ExecutionStatus,
            name="remediation_event_from_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        )
    )
    to_status: Mapped[ExecutionStatus] = mapped_column(
        Enum(
            ExecutionStatus,
            name="remediation_event_to_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    evidence: Mapped[dict] = mapped_column(json_type, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)

    execution: Mapped[RemediationExecution] = relationship(back_populates="events")


class MonitoringRun(TenantScopedMixin, Base):
    __tablename__ = "monitoring_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_monitoring_runs_tenant_id"),
        UniqueConstraint(
            "tenant_id", "schedule_key", name="uq_monitoring_runs_tenant_schedule_key"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    schedule_key: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[MonitoringStatus] = mapped_column(
        Enum(
            MonitoringStatus,
            name="monitoring_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
        default=MonitoringStatus.PENDING,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict] = mapped_column(json_type, nullable=False, default=dict)

    steps: Mapped[list["MonitoringStep"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="MonitoringStep.sequence",
        lazy="selectin",
    )


class MonitoringStep(TenantScopedMixin, Base):
    __tablename__ = "monitoring_steps"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "run_id", "sequence", name="uq_monitoring_steps_tenant_run_id_sequence"
        ),
        tenant_foreign_key(
            "run_id",
            "monitoring_runs",
            "fk_monitoring_steps_tenant_run_id_monitoring_runs",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[MonitoringStatus] = mapped_column(
        Enum(
            MonitoringStatus,
            name="monitoring_step_status",
            native_enum=False,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    output: Mapped[dict] = mapped_column(json_type, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)

    run: Mapped[MonitoringRun] = relationship(back_populates="steps")


class ConnectorScopeBinding(TenantScopedMixin, Base):
    __tablename__ = "connector_scope_bindings"
    __table_args__ = (
        CheckConstraint("connector = lower(connector)", name="ck_connector_scope_connector_lower"),
        CheckConstraint("scope = lower(scope)", name="ck_connector_scope_scope_lower"),
        UniqueConstraint("tenant_id", "id", name="uq_connector_scope_bindings_tenant_id"),
        UniqueConstraint(
            "connector", "scope", name="uq_connector_scope_bindings_connector_scope"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    approval_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ConnectorCheckpoint(TenantScopedMixin, Base):
    __tablename__ = "connector_checkpoints"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "connector",
            "scope",
            name="uq_connector_checkpoints_tenant_connector_scope",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    endpoint_cache: Mapped[dict] = mapped_column(json_type, nullable=False)


@event.listens_for(AuditEvent, "before_update")
@event.listens_for(AuditEvent, "before_delete")
def prevent_audit_event_mutation(*_: object) -> None:
    raise ValueError("Audit events are append-only")


@event.listens_for(PolicyEvaluation, "before_update")
@event.listens_for(PolicyEvaluation, "before_delete")
def prevent_policy_evaluation_mutation(*_: object) -> None:
    raise ValueError("Policy evaluations are immutable")


@event.listens_for(RoleTransition, "before_update")
@event.listens_for(RoleTransition, "before_delete")
def prevent_role_transition_mutation(*_: object) -> None:
    raise ValueError("Role transitions are immutable")


@event.listens_for(RiskAssessment, "before_update")
@event.listens_for(RiskAssessment, "before_delete")
def prevent_risk_assessment_mutation(*_: object) -> None:
    raise ValueError("Risk assessments are immutable")


@event.listens_for(AnomalyModelRun, "before_update")
@event.listens_for(AnomalyModelRun, "before_delete")
@event.listens_for(AnomalyResult, "before_update")
@event.listens_for(AnomalyResult, "before_delete")
def prevent_anomaly_evidence_mutation(*_: object) -> None:
    raise ValueError("Anomaly evidence is immutable")


@event.listens_for(ReviewEvent, "before_update")
@event.listens_for(ReviewEvent, "before_delete")
def prevent_review_event_mutation(*_: object) -> None:
    raise ValueError("Review events are immutable")


@event.listens_for(RemediationExecutionEvent, "before_update")
@event.listens_for(RemediationExecutionEvent, "before_delete")
def prevent_remediation_execution_event_mutation(*_: object) -> None:
    raise ValueError("Remediation execution events are immutable")


@event.listens_for(MonitoringStep, "before_update")
@event.listens_for(MonitoringStep, "before_delete")
def prevent_monitoring_step_mutation(*_: object) -> None:
    raise ValueError("Monitoring steps are immutable")
