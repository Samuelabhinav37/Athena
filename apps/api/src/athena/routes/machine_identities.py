from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.database import get_db_session
from athena.schemas import MachineIdentityPostureResponse
from athena.services.machine_identities import load_machine_identity_posture

router = APIRouter(
    prefix="/v1/machine-identities",
    tags=["machine-identities"],
    dependencies=[Depends(require_viewer)],
)


@router.get("", response_model=list[MachineIdentityPostureResponse])
def list_machine_identities(
    session: Annotated[Session, Depends(get_db_session)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[MachineIdentityPostureResponse]:
    posture = load_machine_identity_posture(session)
    page = posture[offset : offset + limit]
    return [MachineIdentityPostureResponse.model_validate(item) for item in page]
