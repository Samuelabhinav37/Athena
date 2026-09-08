from fastapi import FastAPI, HTTPException, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from athena.database import get_session_factory
from athena.observability import RequestObservabilityMiddleware, metrics
from athena.routes.attack_paths import router as attack_paths_router
from athena.routes.auth import router as auth_router
from athena.routes.connectors import router as connectors_router
from athena.routes.executions import router as executions_router
from athena.routes.identities import router as identities_router
from athena.routes.machine_identities import router as machine_identities_router
from athena.routes.monitoring import router as monitoring_router
from athena.routes.reports import router as reports_router
from athena.routes.reviewers import router as reviewers_router
from athena.routes.reviews import router as reviews_router
from athena.routes.security_events import router as security_events_router
from athena.routes.telemetry import router as telemetry_router
from athena.routes.telemetry import webhook_router

app = FastAPI(
    title="Athena API",
    description="Continuous authorization provenance and identity-governance evidence.",
    version="0.1.0",
)
app.add_middleware(RequestObservabilityMiddleware)

app.include_router(identities_router)
app.include_router(attack_paths_router)
app.include_router(auth_router)
app.include_router(executions_router)
app.include_router(connectors_router)
app.include_router(monitoring_router)
app.include_router(machine_identities_router)
app.include_router(reviews_router)
app.include_router(reviewers_router)
app.include_router(reports_router)
app.include_router(security_events_router)
app.include_router(telemetry_router)
app.include_router(webhook_router)


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    """Report whether the API process is available."""
    return {"status": "ok", "service": "athena-api"}


@app.get("/metrics", tags=["operations"], include_in_schema=False)
def prometheus_metrics() -> Response:
    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")


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
