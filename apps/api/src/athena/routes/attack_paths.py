import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.repositories import IdentityRepository
from athena.schemas import AttackPathResponse
from athena.services.attack_paths import AttackPathError, Neo4jAttackPathAdapter

router = APIRouter(
    prefix="/v1/attack-paths", tags=["attack-paths"], dependencies=[Depends(require_viewer)]
)


@router.get("/identities/{identity_id}", response_model=list[AttackPathResponse])
def list_attack_paths(
    identity_id: uuid.UUID,
    settings: Annotated[Settings, Depends(get_settings)],
    session: Annotated[Session, Depends(get_db_session)],
    max_depth: Annotated[int, Query(ge=1, le=8)] = 6,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> list[AttackPathResponse]:
    if IdentityRepository(session).get(identity_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    try:
        with Neo4jAttackPathAdapter(settings) as adapter:
            paths = adapter.find_privileged_paths(
                identity_id, max_depth=max_depth, limit=limit
            )
            return [AttackPathResponse.model_validate(path) for path in paths]
    except AttackPathError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)
        ) from error
