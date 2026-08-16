import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Table,
    UniqueConstraint,
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
