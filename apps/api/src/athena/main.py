from fastapi import FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from athena.database import get_session_factory
from athena.routes.connectors import router as connectors_router
from athena.routes.identities import router as identities_router
from athena.routes.monitoring import router as monitoring_router
from athena.routes.reviews import router as reviews_router

app = FastAPI(
    title="Athena API",
    description="Continuous authorization provenance and identity-governance evidence.",
    version="0.1.0",
)

app.include_router(identities_router)
app.include_router(connectors_router)
app.include_router(monitoring_router)
app.include_router(reviews_router)


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    """Report whether the API process is available."""
    return {"status": "ok", "service": "athena-api"}


@app.get("/ready", tags=["operations"])
def readiness() -> dict[str, str]:
    """Report whether required infrastructure is reachable."""
    try:
        with get_session_factory()() as session:
            session.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from error
    return {"status": "ready", "database": "available"}
