import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from athena.models import (
    GrantSubjectType,
    IdentityType,
    MonitoringStatus,
    PolicyDecision,
    ResourceType,
    ReviewDecision,
    ReviewStatus,
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


class ReviewEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    occurred_at: datetime
    actor: str
    action: str
    from_status: ReviewStatus | None
    to_status: ReviewStatus
    decision: ReviewDecision | None
    reason: str
    evidence_snapshot: dict
    execution_status: str


class ReviewCaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    identity_id: uuid.UUID
    entitlement_id: uuid.UUID | None
    risk_assessment_id: uuid.UUID | None
    anomaly_result_id: uuid.UUID | None
    title: str
    status: ReviewStatus
    owner: str | None
    due_at: datetime
    resolution: ReviewDecision | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    events: list[ReviewEventResponse]


class OpenReviewRequest(BaseModel):
    identity_id: uuid.UUID
    actor: str = Field(min_length=1, max_length=255)
    owner: str | None = Field(default=None, min_length=1, max_length=255)
    due_days: int = Field(default=7, ge=1, le=90)


class AssignReviewRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=255)
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class DecideReviewRequest(BaseModel):
    decision: ReviewDecision
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=2000)


class MonitoringStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    sequence: int
    attempt: int
    name: str
    status: MonitoringStatus
    started_at: datetime
    completed_at: datetime
    output: dict
    error: str | None


class MonitoringRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    schedule_key: str
    status: MonitoringStatus
    attempt_count: int
    requested_by: str
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    summary: dict
    steps: list[MonitoringStepResponse]


class ConnectorCheckpointResponse(BaseModel):
    id: uuid.UUID
    connector: str
    scope: str
    observed_at: datetime
    fingerprint: str
    cached_endpoints: int
