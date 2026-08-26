from enum import StrEnum
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from athena.models import IdentityType

CONNECTOR_CONTRACT_VERSION = "1.0"


class ConnectorCapability(StrEnum):
    IDENTITY_DISCOVERY = "identity_discovery"
    PAGINATION = "pagination"
    INCREMENTAL_CURSORS = "incremental_cursors"
    RETRIES = "retries"
    COLLECTION_FRESHNESS = "collection_freshness"
    AUTHORIZATION_INHERITANCE = "authorization_inheritance"
    NESTED_GROUPS = "nested_groups"
    DENY_RULES = "deny_rules"
    PRIVILEGED_ELIGIBILITY = "privileged_eligibility"
    MACHINE_IDENTITIES = "machine_identities"
    ACTIVITY_SIGNALS = "activity_signals"


class CapabilitySupport(StrEnum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class ConnectorCapabilityDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    support: CapabilitySupport
    detail: str = Field(min_length=1, max_length=500)


class ConnectorManifest(BaseModel):
    """Portable, secret-free declaration of an IAM connector's evidence boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[CONNECTOR_CONTRACT_VERSION] = CONNECTOR_CONTRACT_VERSION
    connector_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    display_name: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=128)
    read_only: Literal[True] = True
    data_authority: Literal["evidence_only"] = "evidence_only"
    capabilities: dict[ConnectorCapability, ConnectorCapabilityDeclaration]

    @field_validator("capabilities")
    @classmethod
    def require_complete_capability_set(
        cls, value: dict[ConnectorCapability, ConnectorCapabilityDeclaration]
    ) -> dict[ConnectorCapability, ConnectorCapabilityDeclaration]:
        missing = set(ConnectorCapability) - set(value)
        if missing:
            names = ", ".join(sorted(item.value for item in missing))
            raise ValueError(f"connector manifest is missing capabilities: {names}")
        return value

    @model_validator(mode="after")
    def require_explicit_limitations(self) -> "ConnectorManifest":
        for capability, declaration in self.capabilities.items():
            if (
                declaration.support is not CapabilitySupport.SUPPORTED
                and len(declaration.detail) < 12
            ):
                raise ValueError(f"{capability.value} limitation detail is too short")
        return self


class IAMConnector(Protocol):
    @classmethod
    def manifest(cls) -> ConnectorManifest: ...


class NormalizedGroup(BaseModel):
    external_id: str
    name: str
    path: str


class NormalizedRole(BaseModel):
    external_id: str
    name: str
    description: str | None = None


class NormalizedIdentity(BaseModel):
    source: str
    external_id: str
    username: str
    identity_type: IdentityType
    display_name: str
    email: str | None = None
    department: str | None = None
    job_title: str | None = None
    manager_external_id: str | None = None
    active: bool
    source_metadata: dict = Field(default_factory=dict)
    groups: list[NormalizedGroup] = Field(default_factory=list)
    roles: list[NormalizedRole] = Field(default_factory=list)
