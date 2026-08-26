from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

POLICY_REQUEST_SCHEMA = "https://athena.example/schemas/policy-request/2.0"


class PolicyPrincipal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    type: Literal["human", "service_account", "workload", "application", "api_client"]
    username: str = Field(min_length=1, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    roles: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()


class PolicyAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    verb: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    privileged: bool


class PolicyResource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    external_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=128)
    sensitivity: str = Field(min_length=1, max_length=64)


class PolicyGovernanceContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gaps: tuple[str, ...] = ()
    requested_by: str | None = Field(default=None, max_length=255)
    approved_by: str | None = Field(default=None, max_length=255)
    business_reason: str | None = Field(default=None, max_length=2000)
    policy_reference: str | None = Field(default=None, max_length=255)
    granted_at: str
    expires_at: str | None = None


class PolicyAuthenticationContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str = Field(min_length=1, max_length=128)
    phishing_resistant: bool


class PolicyProvenanceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=0)
    from_type: str = Field(min_length=1, max_length=128)
    relationship: str = Field(min_length=1, max_length=128)
    to_type: str = Field(min_length=1, max_length=128)


class PolicyRequestContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    governance: PolicyGovernanceContext
    authentication: PolicyAuthenticationContext
    provenance: tuple[PolicyProvenanceEdge, ...] = ()


class CanonicalPolicyRequest(BaseModel):
    """Engine-neutral request; adapters own any engine-specific representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_url: Literal[POLICY_REQUEST_SCHEMA] = POLICY_REQUEST_SCHEMA
    schema_version: Literal["2.0"] = "2.0"
    principal: PolicyPrincipal
    action: PolicyAction
    resource: PolicyResource
    context: PolicyRequestContext

    def to_opa_v1_input(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "identity": {
                "id": self.principal.id,
                "username": self.principal.username,
                "department": self.principal.department,
                "roles": list(self.principal.roles),
                "groups": list(self.principal.groups),
            },
            "resource": self.resource.model_dump(mode="json"),
            "permission": {
                "id": self.action.id,
                "action": self.action.verb,
                "name": self.action.name,
                "privileged": self.action.privileged,
            },
            "governance": self.context.governance.model_dump(mode="json"),
            "authentication": self.context.authentication.model_dump(mode="json"),
            "provenance": [item.model_dump(mode="json") for item in self.context.provenance],
        }
