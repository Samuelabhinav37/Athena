import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from athena.database import get_db_session
from athena.models import Identity
from athena.schemas import (
    AssignReviewRequest,
    DecideReviewRequest,
    OpenReviewRequest,
    ReviewCaseResponse,
)
from athena.services.remediation import RemediationService, load_case, load_cases

router = APIRouter(prefix="/v1/reviews", tags=["reviews"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def _case_or_404(session: Session, case_id: uuid.UUID):
    case = load_case(session, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    return case


@router.get("", response_model=list[ReviewCaseResponse])
def list_reviews(session: DatabaseSession) -> list[ReviewCaseResponse]:
    return list(load_cases(session))


@router.get("/{case_id}", response_model=ReviewCaseResponse)
def get_review(case_id: uuid.UUID, session: DatabaseSession) -> ReviewCaseResponse:
    return _case_or_404(session, case_id)


@router.post("", response_model=ReviewCaseResponse, status_code=status.HTTP_201_CREATED)
def open_review(request: OpenReviewRequest, session: DatabaseSession) -> ReviewCaseResponse:
    identity = session.get(Identity, request.identity_id)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    try:
        result = RemediationService(session).open_for_latest_evidence(
            identity, request.actor, request.owner, request.due_days
        )
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    return _case_or_404(session, result.case_id)


@router.post("/{case_id}/assign", response_model=ReviewCaseResponse)
def assign_review(
    case_id: uuid.UUID, request: AssignReviewRequest, session: DatabaseSession
) -> ReviewCaseResponse:
    case = _case_or_404(session, case_id)
    try:
        RemediationService(session).assign(case, request.owner, request.actor, request.reason)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    return _case_or_404(session, case_id)


@router.post("/{case_id}/decide", response_model=ReviewCaseResponse)
def decide_review(
    case_id: uuid.UUID, request: DecideReviewRequest, session: DatabaseSession
) -> ReviewCaseResponse:
    case = _case_or_404(session, case_id)
    try:
        RemediationService(session).decide(case, request.decision, request.actor, request.reason)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
    return _case_or_404(session, case_id)
