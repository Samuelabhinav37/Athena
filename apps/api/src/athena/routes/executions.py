import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from athena.auth import AdministratorPrincipal, require_administrator
from athena.database import get_db_session
from athena.schemas import CreateExecutionRequest, RemediationExecutionResponse
from athena.services.execution import (
    ExecutionError,
    ExecutionService,
    load_execution,
    load_executions,
)
from athena.services.remediation import load_case

router = APIRouter(
    prefix="/v1/executions",
    tags=["remediation execution"],
    dependencies=[Depends(require_administrator)],
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=list[RemediationExecutionResponse])
def list_execution_requests(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[RemediationExecutionResponse]:
    return list(load_executions(session, limit=limit, offset=offset))


@router.get("/{execution_id}", response_model=RemediationExecutionResponse)
def get_execution_request(
    execution_id: uuid.UUID, session: DatabaseSession
) -> RemediationExecutionResponse:
    execution = load_execution(session, execution_id)
    if execution is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return execution


@router.post("", response_model=RemediationExecutionResponse, status_code=status.HTTP_201_CREATED)
def create_execution_request(
    request: CreateExecutionRequest,
    session: DatabaseSession,
    principal: AdministratorPrincipal,
) -> RemediationExecutionResponse:
    case = load_case(session, request.case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    if not case.target_snapshot:
        raise HTTPException(status_code=409, detail="Legacy approval requires a fresh bound review")
    try:
        return ExecutionService(session).request(case, principal.actor, request.idempotency_key)
    except ExecutionError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error
