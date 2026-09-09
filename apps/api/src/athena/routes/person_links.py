import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from athena.auth import AdministratorPrincipal, require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session
from athena.models import PersonLink
from athena.routes.reviews import _mutate
from athena.services.person_links import PersonLinkService, link_packet
from athena.tenant_queries import tenant_select

router = APIRouter(
    prefix="/v1/person-links", tags=["person-links"], dependencies=[Depends(require_viewer)]
)
DatabaseSession = Annotated[Session, Depends(get_db_session)]
RuntimeSettings = Annotated[Settings, Depends(get_settings)]


class Proposal(BaseModel):
    anchor_id: uuid.UUID
    account_id: uuid.UUID
    evidence_kind: Literal["synthetic_fixture", "directory_admin_attestation", "hr_record"]
    evidence_reference: str = Field(min_length=10, max_length=1000)
    reason: str = Field(min_length=10, max_length=2000)


class Transition(BaseModel):
    revision: int = Field(ge=1)
    action: Literal["confirmed", "rejected", "revoked"]
    reason: str = Field(min_length=10, max_length=2000)


@router.get("")
def list_links(
    session: DatabaseSession,
    account_id: uuid.UUID,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    links = session.scalars(
        tenant_select(
            session,
            PersonLink,
            PersonLink.account_id == account_id,
        )
        .order_by(PersonLink.created_at.desc(), PersonLink.id)
        .limit(limit)
        .offset(offset)
    )
    return [link_packet(link) for link in links]


@router.post("", status_code=201)
def propose(
    request: Proposal,
    session: DatabaseSession,
    settings: RuntimeSettings,
    principal: AdministratorPrincipal,
):
    return _mutate(
        session,
        lambda: link_packet(
            PersonLinkService(session, settings).propose(
                request.anchor_id,
                request.account_id,
                request.evidence_kind,
                request.evidence_reference,
                request.reason,
                principal,
            )
        ),
    )


@router.post("/{link_id}/transition")
def transition(
    link_id: uuid.UUID,
    request: Transition,
    session: DatabaseSession,
    settings: RuntimeSettings,
    principal: AdministratorPrincipal,
):
    return _mutate(
        session,
        lambda: link_packet(
            PersonLinkService(session, settings).transition(
                link_id,
                request.revision,
                request.action,
                request.reason,
                principal,
            )
        ),
    )
