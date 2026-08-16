import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from athena.database import get_db_session
from athena.repositories import IdentityRepository
from athena.schemas import IdentityResponse

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
