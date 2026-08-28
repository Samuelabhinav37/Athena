from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.database import get_db_session
from athena.schemas import MonitoringRunResponse
from athena.services.monitoring import load_monitoring_runs

router = APIRouter(
    prefix="/v1/monitoring", tags=["monitoring"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("/runs", response_model=list[MonitoringRunResponse])
def list_runs(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[MonitoringRunResponse]:
    return list(load_monitoring_runs(session, limit=limit, offset=offset))
