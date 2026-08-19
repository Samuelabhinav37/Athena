import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.repositories import IdentityRepository
from athena.schemas import (
    AnomalyResultResponse,
    EntitlementResponse,
    GrantGovernanceResponse,
    IdentityExplanationResponse,
    IdentityResponse,
    PermissionSummary,
    PolicyEvaluationResponse,
    ProvenanceEdgeResponse,
    RiskAssessmentResponse,
    RiskFindingResponse,
)
from athena.services.explanations import (
    ExplanationError,
    ExplanationService,
    build_ai_provider,
)
from athena.services.peer_anomaly import load_anomaly_results
from athena.services.policy_evaluation import load_policy_evaluations
from athena.services.provenance import governance_gaps, load_identity_entitlements
from athena.services.risk_analytics import load_risk_assessments

router = APIRouter(
    prefix="/v1/identities", tags=["identities"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


@router.get("", response_model=list[IdentityResponse])
def list_identities(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[IdentityResponse]:
    return IdentityRepository(session).list(limit=limit, offset=offset)


@router.get("/{identity_id}", response_model=IdentityResponse)
def get_identity(identity_id: uuid.UUID, session: DatabaseSession) -> IdentityResponse:
    identity = IdentityRepository(session).get(identity_id)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    return identity


@router.get("/{identity_id}/entitlements", response_model=list[EntitlementResponse])
def list_identity_entitlements(
    identity_id: uuid.UUID, session: DatabaseSession
) -> list[EntitlementResponse]:
    if IdentityRepository(session).get(identity_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")

    responses = []
    for entitlement in load_identity_entitlements(session, identity_id):
        grant = entitlement.grant
        gaps = governance_gaps(grant)
        responses.append(
            EntitlementResponse(
                id=entitlement.id,
                identity_id=entitlement.identity_id,
                permission=PermissionSummary.model_validate(entitlement.permission),
                grant_id=grant.id,
                subject_type=grant.subject_type,
                governance=GrantGovernanceResponse(
                    status="ungoverned" if gaps else "governed",
                    gaps=gaps,
                    business_reason=grant.business_reason,
                    approved_by=grant.approved_by.username if grant.approved_by else None,
                    policy_reference=grant.policy_reference,
                    granted_at=grant.granted_at,
                    expires_at=grant.expires_at,
                ),
                provenance=[
                    ProvenanceEdgeResponse.model_validate(edge)
                    for edge in entitlement.provenance_edges
                ],
                computed_at=entitlement.computed_at,
            )
        )
    return responses


@router.get(
    "/{identity_id}/policy-evaluations",
    response_model=list[PolicyEvaluationResponse],
)
def list_identity_policy_evaluations(
    identity_id: uuid.UUID, session: DatabaseSession
) -> list[PolicyEvaluationResponse]:
    if IdentityRepository(session).get(identity_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    return list(load_policy_evaluations(session, identity_id))


@router.get(
    "/{identity_id}/risk-assessments",
    response_model=list[RiskAssessmentResponse],
)
def list_identity_risk_assessments(
    identity_id: uuid.UUID, session: DatabaseSession
) -> list[RiskAssessmentResponse]:
    if IdentityRepository(session).get(identity_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    responses = []
    for assessment in load_risk_assessments(session, identity_id):
        responses.append(
            RiskAssessmentResponse(
                id=assessment.id,
                identity_id=assessment.identity_id,
                evaluated_at=assessment.evaluated_at,
                model_version=assessment.model_version,
                score=assessment.score,
                level=assessment.level,
                peer_definition=assessment.peer_definition,
                summary=assessment.summary,
                findings=[
                    RiskFindingResponse(
                        id=finding.id,
                        entitlement_id=finding.entitlement_id,
                        finding_type=finding.finding_type,
                        score=finding.score,
                        permission=finding.entitlement.permission.name,
                        resource=finding.entitlement.permission.resource.name,
                        factors=finding.factors,
                        explanation=finding.explanation,
                    )
                    for finding in assessment.findings
                ],
            )
        )
    return responses


@router.get("/{identity_id}/anomaly-assessments", response_model=list[AnomalyResultResponse])
def list_identity_anomaly_assessments(
    identity_id: uuid.UUID, session: DatabaseSession
) -> list[AnomalyResultResponse]:
    if IdentityRepository(session).get(identity_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    return list(load_anomaly_results(session, identity_id))


@router.post("/{identity_id}/explanation", response_model=IdentityExplanationResponse)
def explain_identity(
    identity_id: uuid.UUID,
    session: DatabaseSession,
    settings: RuntimeSettings,
) -> IdentityExplanationResponse:
    identity = IdentityRepository(session).get(identity_id)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    try:
        return ExplanationService(session, build_ai_provider(settings)).explain(identity)
    except ExplanationError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(error),
        ) from error
