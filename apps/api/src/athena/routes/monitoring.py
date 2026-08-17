from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from athena.database import get_db_session
from athena.schemas import MonitoringRunResponse
from athena.services.monitoring import load_monitoring_runs

router = APIRouter(prefix="/v1/monitoring", tags=["monitoring"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("/runs", response_model=list[MonitoringRunResponse])
def list_runs(session: DatabaseSession) -> list[MonitoringRunResponse]:
    return list(load_monitoring_runs(session))
