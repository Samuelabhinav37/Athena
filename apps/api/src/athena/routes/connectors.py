from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.database import get_db_session
from athena.models import ConnectorCheckpoint
from athena.schemas import ConnectorCheckpointResponse

router = APIRouter(
    prefix="/v1/connectors", tags=["connectors"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=list[ConnectorCheckpointResponse])
def list_connector_checkpoints(
    session: DatabaseSession,
) -> list[ConnectorCheckpointResponse]:
    checkpoints = session.scalars(
        select(ConnectorCheckpoint).order_by(
            ConnectorCheckpoint.connector, ConnectorCheckpoint.scope
        )
    )
    return [
        ConnectorCheckpointResponse(
            id=checkpoint.id,
            connector=checkpoint.connector,
            scope=checkpoint.scope,
            observed_at=checkpoint.observed_at,
            fingerprint=checkpoint.fingerprint,
            cached_endpoints=len(checkpoint.endpoint_cache),
        )
        for checkpoint in checkpoints
    ]
