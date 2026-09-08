import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from athena.auth import AnalystPrincipal, ReviewerPrincipal, require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.repositories import IdentityRepository
from athena.schemas import (
    AssignReviewRequest,
    DecideReviewRequest,
    FulfillmentRequest,
    OpenReviewRequest,
    ReviewCaseResponse,
    VerifyReviewRequest,
)
from athena.services.bound_reviews import BoundReviewService
from athena.services.remediation import load_case, load_cases
from athena.services.review_worker import ReviewRetryWorker

router = APIRouter(prefix="/v1/reviews", tags=["reviews"], dependencies=[Depends(require_viewer)])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


def _mutate(session: Session, operation):
    try:
        return operation()
    except (ValueError, IntegrityError, StaleDataError) as error:
        session.rollback()
        detail = str(error) if isinstance(error, ValueError) else "Review changed; reload and retry"
        raise HTTPException(status_code=409, detail=detail) from error


def _case_or_404(session: Session, case_id: uuid.UUID):
    case = load_case(session, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    return case


@router.get("", response_model=list[ReviewCaseResponse])
def list_reviews(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReviewCaseResponse]:
    return list(load_cases(session, limit=limit, offset=offset))


@router.get("/{case_id}", response_model=ReviewCaseResponse)
def get_review(case_id: uuid.UUID, session: DatabaseSession) -> ReviewCaseResponse:
    return _case_or_404(session, case_id)


@router.post("", response_model=ReviewCaseResponse, status_code=status.HTTP_201_CREATED)
def open_review(
    request: OpenReviewRequest,
    session: DatabaseSession,
    principal: AnalystPrincipal,
    settings: RuntimeSettings,
) -> ReviewCaseResponse:
    identity = IdentityRepository(session).get(request.identity_id)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    if request.owner:
        raise HTTPException(status_code=409, detail="Assign an immutable reviewer after opening")
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).open(
            identity.id,
            request.finding_id,
            request.policy_evaluation_id,
            request.proposed_action,
            request.closure_goal,
            request.due_days,
            principal,
        ),
    )


@router.post("/{case_id}/assign", response_model=ReviewCaseResponse)
def assign_review(
    case_id: uuid.UUID,
    request: AssignReviewRequest,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
) -> ReviewCaseResponse:
    case = _case_or_404(session, case_id)
    if request.owner_id is None or request.revision is None or request.owner:
        raise HTTPException(status_code=409, detail="Immutable owner_id and revision are required")
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).assign(
            case.id,
            request.revision,
            request.owner_id,
            principal,
            request.reason,
        ),
    )


@router.post("/{case_id}/decide", response_model=ReviewCaseResponse)
def decide_review(
    case_id: uuid.UUID,
    request: DecideReviewRequest,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
) -> ReviewCaseResponse:
    case = _case_or_404(session, case_id)
    if request.revision is None:
        raise HTTPException(status_code=409, detail="A bound review and revision are required")
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).decide(
            case.id,
            request.revision,
            request.decision,
            principal,
            request.reason,
        ),
    )


@router.post("/{case_id}/fulfillment", response_model=ReviewCaseResponse)
def fulfill_review(
    case_id: uuid.UUID,
    request: FulfillmentRequest,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
    response: Response,
):
    _case_or_404(session, case_id)
    case = _mutate(
        session,
        lambda: BoundReviewService(session, settings).fulfill(
            case_id,
            request.revision,
            request.operator_id,
            principal,
            request.reason,
            request.complete,
            request.due_days,
        ),
    )
    if request.complete:
        response.status_code = status.HTTP_202_ACCEPTED
    return case


@router.post("/{case_id}/verify", response_model=ReviewCaseResponse, status_code=202)
def verify_review(
    case_id: uuid.UUID,
    request: VerifyReviewRequest,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
):
    _case_or_404(session, case_id)
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).request_verification(
            case_id,
            request.revision,
            principal,
        ),
    )


@router.get("/{case_id}/collection-status")
def collection_status(case_id: uuid.UUID, session: DatabaseSession, settings: RuntimeSettings):
    case = _case_or_404(session, case_id)
    return ReviewRetryWorker(session, settings).collection_status(case)


@router.post("/{case_id}/cancel", response_model=ReviewCaseResponse)
def cancel_review(
    case_id: uuid.UUID,
    request: DecideReviewRequest,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
):
    _case_or_404(session, case_id)
    if request.revision is None:
        raise HTTPException(status_code=409, detail="A case revision is required")
    return _mutate(
        session,
        lambda: BoundReviewService(session, settings).cancel(
            case_id,
            request.revision,
            principal,
            request.reason,
        ),
    )


@router.get("/{case_id}/evidence")
def review_evidence(
    case_id: uuid.UUID,
    session: DatabaseSession,
    principal: ReviewerPrincipal,
    settings: RuntimeSettings,
):
    _case_or_404(session, case_id)
    return BoundReviewService(session, settings).report(case_id)
