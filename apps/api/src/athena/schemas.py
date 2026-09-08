import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from athena.models import (
    ExecutionStatus,
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


class IdentityPageResponse(BaseModel):
    items: list[IdentityResponse]
    total: int
    limit: int
    offset: int


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


class AttackPathNodeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    label: str


class AttackPathResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    nodes: tuple[AttackPathNodeResponse, ...]
    relationships: tuple[str, ...]


class MachineIdentityFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    severity: str
    summary: str


class MachineIdentityPostureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    identity_id: uuid.UUID
    username: str
    display_name: str
    identity_type: IdentityType
    source: str
    active: bool
    owner: str | None
    active_entitlements: int
    privileged_entitlements: int
    last_used_at: datetime | None
    findings: tuple[MachineIdentityFindingResponse, ...]


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
    owner_id: uuid.UUID | None
    revision: int
    policy_evaluation_id: uuid.UUID | None
    target_snapshot: dict | None
    due_at: datetime
    resolution: ReviewDecision | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
    events: list[ReviewEventResponse]


class OpenReviewRequest(BaseModel):
    identity_id: uuid.UUID
    owner: str | None = Field(default=None, min_length=1, max_length=255)
    due_days: int = Field(default=7, ge=1, le=90)
    finding_id: uuid.UUID | None = None
    policy_evaluation_id: uuid.UUID | None = None
    proposed_action: ReviewDecision = ReviewDecision.RETAIN
    closure_goal: str = "record_decision"


class AssignReviewRequest(BaseModel):
    owner: str | None = Field(default=None, min_length=1, max_length=255)
    owner_id: uuid.UUID | None = None
    revision: int | None = Field(default=None, ge=1)
    reason: str = Field(min_length=1, max_length=2000)


class DecideReviewRequest(BaseModel):
    decision: ReviewDecision
    reason: str = Field(min_length=10, max_length=2000)
    revision: int | None = Field(default=None, ge=1)


class ReviewerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    identity_id: uuid.UUID
    issuer: str
    subject: str
    display_name: str
    active: bool


class RegisterReviewerRequest(BaseModel):
    identity_id: uuid.UUID
    reason: str = Field(min_length=10, max_length=2000)


class ReviewerEligibilityRequest(BaseModel):
    active: bool
    reason: str = Field(min_length=10, max_length=2000)


class FulfillmentRequest(BaseModel):
    revision: int = Field(ge=1)
    operator_id: uuid.UUID | None = None
    complete: bool = False
    due_days: int = Field(default=7, ge=1, le=90)
    reason: str = Field(min_length=10, max_length=2000)


class VerifyReviewRequest(BaseModel):
    revision: int = Field(ge=1)


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


class ConnectorScopeResponse(BaseModel):
    id: uuid.UUID
    connector: str
    scope: str
    approval_reference: str
    approved_by: str
    approved_at: datetime
    active: bool
    revoked_at: datetime | None
    revocation_reference: str | None


class AuthenticatedPrincipalResponse(BaseModel):
    subject: str
    username: str
    roles: list[str]


class GeneratedExplanationContent(BaseModel):
    summary: str = Field(min_length=1, max_length=4000)
    findings: list[str] = Field(max_length=20)
    limitations: list[str] = Field(max_length=20)


class IdentityExplanationResponse(GeneratedExplanationContent):
    identity_id: uuid.UUID
    generated_at: datetime
    model: str
    provider: str
    provider_metadata: dict[str, str]
    evidence_digest: str
    evidence_references: list[str]
    disclaimer: str


class EvidenceControlResponse(BaseModel):
    control_id: str
    title: str
    status: str
    automated_checks: int
    limitations: list[str]


class EvidenceReportResponse(BaseModel):
    schema_version: str
    generated_at: datetime
    scope: str
    inventory: dict[str, int | float | None]
    policy_decisions: dict[str, int]
    review_statuses: dict[str, int]
    execution_statuses: dict[str, int]
    monitoring_statuses: dict[str, int]
    controls: list[EvidenceControlResponse]
    authoritative_sources: list[str]
    limitations: list[str]
    evidence_digest: str


class CreateExecutionRequest(BaseModel):
    case_id: uuid.UUID
    idempotency_key: str = Field(min_length=8, max_length=255)


class RemediationExecutionEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    occurred_at: datetime
    actor: str
    action: str
    from_status: ExecutionStatus | None
    to_status: ExecutionStatus
    evidence: dict
    error: str | None


class RemediationExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    case_id: uuid.UUID
    entitlement_id: uuid.UUID
    source: str
    action: str
    target_external_id: str
    idempotency_key: str
    requested_by: str
    status: ExecutionStatus
    attempt_count: int
    started_at: datetime | None
    completed_at: datetime | None
    before_evidence: dict
    after_evidence: dict
    adapter_receipt: dict
    error: str | None
    created_at: datetime
    updated_at: datetime
    events: list[RemediationExecutionEventResponse]


class SecurityAgentEnrollRequest(BaseModel):
    external_id: str = Field(min_length=3, max_length=255, pattern=r"^[A-Za-z0-9._:-]+$")
    agent_type: str = Field(pattern=r"^(moat|clutter)$")
    display_name: str = Field(min_length=1, max_length=255)


class SecurityAgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    external_id: str
    agent_type: str
    display_name: str
    enrolled_by: str
    enrolled_at: datetime


class SecurityAgentEnrollmentResponse(SecurityAgentResponse):
    enrollment_secret: str


class SecurityAgentTokenRequest(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,62}$")
    agent_id: uuid.UUID
    enrollment_secret: str = Field(min_length=32, max_length=255)


class SecurityAgentTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_at: datetime


class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_event_id: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    action: str = Field(pattern=r"^(blocked|warned|quarantined|allowed_override)$")
    severity: str = Field(pattern=r"^(low|medium|high|critical)$")
    rule_id: str = Field(min_length=1, max_length=255)
    policy_version: str | None = Field(default=None, max_length=64)
    subject_pseudonym: str | None = Field(default=None, max_length=128)
    target_indicator: str | None = Field(default=None, max_length=255)
    evidence: dict = Field(default_factory=dict)

    @field_validator("target_indicator")
    @classmethod
    def reject_full_urls_and_addresses(cls, value: str | None) -> str | None:
        if value and ("://" in value or "@" in value or "/" in value):
            raise ValueError("target_indicator must be a minimized domain or digest")
        return value

    @field_validator("evidence")
    @classmethod
    def require_minimized_evidence(cls, value: dict) -> dict:
        import json

        forbidden = {"body", "subject", "email_body", "authorization", "token", "password"}
        if forbidden.intersection(key.lower() for key in value):
            raise ValueError("evidence contains a forbidden sensitive field")
        if len(json.dumps(value, separators=(",", ":")).encode()) > 16_384:
            raise ValueError("evidence exceeds 16 KiB")
        return value


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    agent_id: uuid.UUID
    source_event_id: str
    occurred_at: datetime
    received_at: datetime
    action: str
    severity: str
    rule_id: str
    policy_version: str | None
    subject_pseudonym: str | None
    target_indicator: str | None
    evidence: dict
    evidence_digest: str


class SecurityPolicyPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_type: str = Field(pattern=r"^(moat|clutter)$")
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    policy: dict
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(min_length=16, max_length=8192)
    signing_key_id: str = Field(min_length=1, max_length=128)


class SecurityPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    agent_type: str
    version: str
    policy: dict
    policy_digest: str
    signature: str
    signing_key_id: str
    published_by: str
    published_at: datetime


class SecurityCorrelationResponse(BaseModel):
    """One target_indicator reported by more than one agent_type within the
    query window -- see services/security_correlation.py. Read-only; never
    constructed from a database row via from_attributes, always built
    explicitly from a CrossProductCorrelation dataclass in the route."""

    target_indicator: str
    agent_types: list[str]
    event_count: int
    highest_severity: str
    first_seen: datetime
    last_seen: datetime
    rule_ids: list[str]
