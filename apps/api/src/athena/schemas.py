import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from athena.models import (
    GrantSubjectType,
    IdentityType,
    PolicyDecision,
    ResourceType,
    RiskFindingType,
    RiskLevel,
    Sensitivity,
)


class GroupSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    path: str


class RoleSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None


class IdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    external_id: str
    username: str
    identity_type: IdentityType
    display_name: str
    email: str | None
    department: str | None
    job_title: str | None
    manager_external_id: str | None
    active: bool
    observed_at: datetime
    groups: list[GroupSummary]
    roles: list[RoleSummary]


class ResourceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    resource_type: ResourceType
    sensitivity: Sensitivity


class PermissionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    action: str
    name: str
    privileged: bool
    resource: ResourceSummary


class ProvenanceEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    from_type: str
    from_id: uuid.UUID
    from_label: str
    relationship: str = Field(validation_alias="relationship_type")
    to_type: str
    to_id: uuid.UUID
    to_label: str


class GrantGovernanceResponse(BaseModel):
    status: str
    gaps: list[str]
    business_reason: str | None
    approved_by: str | None
    policy_reference: str | None
    granted_at: datetime
    expires_at: datetime | None


class EntitlementResponse(BaseModel):
    id: uuid.UUID
    identity_id: uuid.UUID
    permission: PermissionSummary
    grant_id: uuid.UUID
    subject_type: GrantSubjectType
    governance: GrantGovernanceResponse
    provenance: list[ProvenanceEdgeResponse]
    computed_at: datetime


class PolicyEvaluationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entitlement_id: uuid.UUID
    evaluated_at: datetime
    engine: str
    policy_path: str
    policy_version: str
    decision: PolicyDecision
    input_snapshot: dict
    violations: list[dict]


class RiskFindingResponse(BaseModel):
    id: uuid.UUID
    entitlement_id: uuid.UUID
    finding_type: RiskFindingType
    score: float
    permission: str
    resource: str
    factors: dict
    explanation: str


class RiskAssessmentResponse(BaseModel):
    id: uuid.UUID
    identity_id: uuid.UUID
    evaluated_at: datetime
    model_version: str
    score: float
    level: RiskLevel
    peer_definition: dict
    summary: dict
    findings: list[RiskFindingResponse]


class AnomalyModelRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    algorithm: str
    library_version: str
    model_version: str
    trained_at: datetime
    random_seed: int
    contamination: float
    feature_schema: list[str]
    training_fingerprint: str
    sample_size: int
    peer_definition: dict
    summary: dict


class AnomalyResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    identity_id: uuid.UUID
    subject_key: str
    score_samples: float
    decision_score: float
    is_anomaly: bool
    features: dict
    explanation: dict
    run: AnomalyModelRunResponse
