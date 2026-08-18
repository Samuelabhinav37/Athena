from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from athena.auth import require_administrator
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.schemas import EvidenceReportResponse
from athena.services.evidence_report import EvidenceReportService

router = APIRouter(
    prefix="/v1/reports",
    tags=["evidence reports"],
    dependencies=[Depends(require_administrator)],
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


@router.get("/evidence", response_model=EvidenceReportResponse)
def evidence_report(
    session: DatabaseSession, settings: RuntimeSettings
) -> EvidenceReportResponse:
    return EvidenceReportService(session, settings.control_directory).build()


@router.get("/evidence.md", response_class=PlainTextResponse)
def evidence_report_markdown(session: DatabaseSession, settings: RuntimeSettings) -> str:
    service = EvidenceReportService(session, settings.control_directory)
    return service.markdown(service.build())
