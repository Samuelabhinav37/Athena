from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from athena.auth import require_viewer
from athena.database import get_db_session
from athena.models import ConnectorCheckpoint, ConnectorScopeBinding, ConnectorScopeRevocation
from athena.schemas import ConnectorCheckpointResponse, ConnectorScopeResponse
from athena.tenant_queries import tenant_select

router = APIRouter(
    prefix="/v1/connectors", tags=["connectors"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=list[ConnectorCheckpointResponse])
def list_connector_checkpoints(
    session: DatabaseSession,
) -> list[ConnectorCheckpointResponse]:
    statement = tenant_select(session, ConnectorCheckpoint).order_by(
        ConnectorCheckpoint.connector, ConnectorCheckpoint.scope
    )
    checkpoints = session.scalars(statement)
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


@router.get("/scopes", response_model=list[ConnectorScopeResponse])
def list_connector_scopes(session: DatabaseSession) -> list[ConnectorScopeResponse]:
    bindings = list(
        session.scalars(
            tenant_select(session, ConnectorScopeBinding).order_by(
                ConnectorScopeBinding.connector, ConnectorScopeBinding.scope
            )
        )
    )
    revocations = {
        revocation.binding_id: revocation
        for revocation in session.scalars(tenant_select(session, ConnectorScopeRevocation))
    }
    return [
        ConnectorScopeResponse(
            id=binding.id,
            connector=binding.connector,
            scope=binding.scope,
            approval_reference=binding.approval_reference,
            approved_by=binding.approved_by,
            approved_at=binding.approved_at,
            active=binding.id not in revocations,
            revoked_at=(revocations[binding.id].revoked_at if binding.id in revocations else None),
            revocation_reference=(
                revocations[binding.id].approval_reference if binding.id in revocations else None
            ),
        )
        for binding in bindings
    ]
