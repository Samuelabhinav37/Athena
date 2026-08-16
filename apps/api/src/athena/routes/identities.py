import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from athena.database import get_db_session
from athena.repositories import IdentityRepository
from athena.schemas import (
    EntitlementResponse,
    GrantGovernanceResponse,
    IdentityResponse,
    PermissionSummary,
    ProvenanceEdgeResponse,
)
from athena.services.provenance import governance_gaps, load_identity_entitlements

router = APIRouter(prefix="/v1/identities", tags=["identities"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


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
