import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from athena.auth import AdministratorPrincipal, require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.models import Reviewer
from athena.routes.reviews import _mutate
from athena.schemas import RegisterReviewerRequest, ReviewerEligibilityRequest, ReviewerResponse
from athena.services.bound_reviews import BoundReviewService
from athena.tenant_queries import tenant_select

router = APIRouter(
    prefix="/v1/reviewers", tags=["reviewers"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


@router.get("", response_model=list[ReviewerResponse])
def list_reviewers(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    return list(
        session.scalars(
            tenant_select(session, Reviewer)
            .order_by(Reviewer.display_name, Reviewer.id)
            .limit(limit)
            .offset(offset)
        )
    )


@router.post("", response_model=ReviewerResponse, status_code=201)
def register_reviewer(
    request: RegisterReviewerRequest,
    session: DatabaseSession,
    principal: AdministratorPrincipal,
    settings: RuntimeSettings,
):
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).register(
            request.identity_id,
            principal,
            request.reason,
        ),
    )


@router.post("/{reviewer_id}/eligibility", response_model=ReviewerResponse)
def reviewer_eligibility(
    reviewer_id: uuid.UUID,
    request: ReviewerEligibilityRequest,
    session: DatabaseSession,
    principal: AdministratorPrincipal,
    settings: RuntimeSettings,
):
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).set_eligible(
            reviewer_id,
            request.active,
            principal,
            request.reason,
        ),
    )
