from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from athena.auth import AdministratorPrincipal, require_viewer
from athena.config import Settings, get_settings
from athena.database import get_db_session, get_session_factory
from athena.models import SecurityAgent, SecurityEvent, SecurityPolicyVersion
from athena.schemas import (
    SecurityAgentEnrollmentResponse,
    SecurityAgentEnrollRequest,
    SecurityAgentResponse,
    SecurityAgentTokenRequest,
    SecurityAgentTokenResponse,
    SecurityCorrelationResponse,
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityPolicyPublishRequest,
    SecurityPolicyResponse,
)
from athena.services.request_controls import RequestControls
from athena.services.security_agents import (
    AgentActionPolicyError,
    AgentAuthenticationError,
    AgentPrincipal,
    canonical_digest,
    create_enrollment_secret,
    evaluate_agent_action,
    issue_agent_token,
    verify_agent_token,
    verify_enrollment_secret,
    verify_policy_signature,
)
from athena.services.security_correlation import find_cross_product_correlations
from athena.tenant_queries import tenant_select

router = APIRouter(prefix="/v1/security", tags=["browser and email security"])
agent_bearer = HTTPBearer(auto_error=False)
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def get_agent_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(agent_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Agent bearer token required")
    try:
        return verify_agent_token(credentials.credentials, settings)
    except AgentAuthenticationError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error


AgentIdentity = Annotated[AgentPrincipal, Depends(get_agent_principal)]


@router.post(
    "/agents", response_model=SecurityAgentEnrollmentResponse, status_code=status.HTTP_201_CREATED
)
def enroll_agent(
    request: SecurityAgentEnrollRequest,
    session: DatabaseSession,
    principal: AdministratorPrincipal,
) -> SecurityAgentEnrollmentResponse:
    secret, salt, digest = create_enrollment_secret()
    agent = SecurityAgent(
        external_id=request.external_id,
        agent_type=request.agent_type,
        display_name=request.display_name,
        credential_salt=salt,
        credential_digest=digest,
        enrolled_by=principal.actor,
    )
    session.add(agent)
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(status_code=409, detail="Security agent is already enrolled") from error
    return SecurityAgentEnrollmentResponse.model_validate(
        {**SecurityAgentResponse.model_validate(agent).model_dump(), "enrollment_secret": secret}
    )


@router.post("/agent-token", response_model=SecurityAgentTokenResponse)
def exchange_agent_token(
    request: SecurityAgentTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecurityAgentTokenResponse:
    with get_session_factory(request.tenant_id)() as session:
        admission = RequestControls(session).admit(
            namespace="security-agent-token",
            subject=str(request.agent_id),
            limit=10,
            window=timedelta(minutes=1),
        )
        session.commit()
        if not admission.allowed:
            raise HTTPException(
                status_code=429,
                detail="Agent token exchange rate limit exceeded",
                headers={"Retry-After": str(admission.retry_after_seconds)},
            )
        agent = session.scalar(
            select(SecurityAgent).where(
                SecurityAgent.tenant_id == request.tenant_id,
                SecurityAgent.id == request.agent_id,
            )
        )
        if agent is None or not verify_enrollment_secret(agent, request.enrollment_secret):
            raise HTTPException(status_code=401, detail="Invalid agent enrollment credential")
        try:
            token, expires_at = issue_agent_token(agent, settings)
        except AgentAuthenticationError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
    return SecurityAgentTokenResponse(access_token=token, expires_at=expires_at)


@router.post("/events", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
def ingest_event(
    request: SecurityEventCreate,
    agent: AgentIdentity,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecurityEventResponse:
    if "events:write" not in agent.capabilities:
        raise HTTPException(status_code=403, detail="Agent token cannot write events")
    # Only override events reach the policy engine -- every other action is
    # already constrained to a fixed set by SecurityEventCreate's own
    # validator, so this stays off the hot path for the common case. See
    # evaluate_agent_action's own docstring for why an unapproved-override
    # check isn't part of this (nothing in the real architecture produces
    # that signal before ingestion).
    if request.action == "allowed_override":
        reason = str(request.evidence.get("override_reason", ""))
        try:
            evaluate_agent_action(settings, request.action, reason)
        except AgentActionPolicyError as error:
            if error.violations:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "message": "Security event denied by policy",
                        "violations": error.violations,
                    },
                ) from error
            raise HTTPException(status_code=503, detail="Policy engine unavailable") from error
    with get_session_factory(agent.tenant_id)() as session:
        admission = RequestControls(session).admit(
            namespace="security-events",
            subject=str(agent.agent_id),
            limit=600,
            window=timedelta(minutes=1),
        )
        if not admission.allowed:
            session.rollback()
            raise HTTPException(
                status_code=429,
                detail="Security event rate limit exceeded",
                headers={"Retry-After": str(admission.retry_after_seconds)},
            )
        enrolled = session.scalar(
            select(SecurityAgent.id).where(
                SecurityAgent.tenant_id == agent.tenant_id,
                SecurityAgent.id == agent.agent_id,
                SecurityAgent.agent_type == agent.agent_type,
            )
        )
        if enrolled is None:
            raise HTTPException(status_code=401, detail="Security agent is not enrolled")
        existing = session.scalar(
            tenant_select(
                session,
                SecurityEvent,
                SecurityEvent.agent_id == agent.agent_id,
                SecurityEvent.source_event_id == request.source_event_id,
            )
        )
        if existing is not None:
            session.commit()
            return existing
        digest = canonical_digest(request.model_dump(mode="json"))
        event = SecurityEvent(
            agent_id=agent.agent_id,
            evidence_digest=digest,
            **request.model_dump(),
        )
        try:
            session.add(event)
            session.commit()
        except IntegrityError:
            session.rollback()
            concurrent = session.scalar(
                tenant_select(
                    session,
                    SecurityEvent,
                    SecurityEvent.agent_id == agent.agent_id,
                    SecurityEvent.source_event_id == request.source_event_id,
                )
            )
            if concurrent is None:
                raise
            return concurrent
        return event


@router.get(
    "/events",
    response_model=list[SecurityEventResponse],
    dependencies=[Depends(require_viewer)],
)
def list_events(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[SecurityEventResponse]:
    return list(
        session.scalars(
            tenant_select(session, SecurityEvent)
            .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )


@router.get(
    "/events/correlations",
    response_model=list[SecurityCorrelationResponse],
    dependencies=[Depends(require_viewer)],
)
def list_cross_product_correlations(
    session: DatabaseSession,
    window_days: Annotated[int, Query(ge=1, le=180)] = 30,
) -> list[SecurityCorrelationResponse]:
    """Domains/indicators reported by more than one agent_type (moat and
    clutter) within the window -- a much higher-confidence signal than
    either product's own detection alone, over evidence that's already
    ingested. See services/security_correlation.py."""
    correlations = find_cross_product_correlations(session, timedelta(days=window_days))
    return [SecurityCorrelationResponse(**vars(c)) for c in correlations]


@router.get(
    "/agents", response_model=list[SecurityAgentResponse], dependencies=[Depends(require_viewer)]
)
def list_agents(session: DatabaseSession) -> list[SecurityAgentResponse]:
    return list(
        session.scalars(
            tenant_select(session, SecurityAgent).order_by(SecurityAgent.enrolled_at.desc())
        )
    )


@router.post(
    "/policies", response_model=SecurityPolicyResponse, status_code=status.HTTP_201_CREATED
)
def publish_policy(
    request: SecurityPolicyPublishRequest,
    session: DatabaseSession,
    principal: AdministratorPrincipal,
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecurityPolicyResponse:
    if canonical_digest(request.policy) != request.policy_digest:
        raise HTTPException(status_code=422, detail="Policy digest does not match policy content")
    if not settings.security_policy_public_key_pem:
        raise HTTPException(
            status_code=503, detail="Policy signature verification is not configured"
        )
    if not verify_policy_signature(
        request.policy, request.signature, settings.security_policy_public_key_pem
    ):
        raise HTTPException(status_code=422, detail="Policy signature is invalid")
    policy = SecurityPolicyVersion(**request.model_dump(), published_by=principal.actor)
    session.add(policy)
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise HTTPException(status_code=409, detail="Policy version already exists") from error
    return policy


@router.get("/policies/latest", response_model=SecurityPolicyResponse)
def latest_policy(agent: AgentIdentity) -> SecurityPolicyResponse:
    if "policies:read" not in agent.capabilities:
        raise HTTPException(status_code=403, detail="Agent token cannot read policies")
    with get_session_factory(agent.tenant_id)() as session:
        policy = session.scalar(
            tenant_select(
                session,
                SecurityPolicyVersion,
                SecurityPolicyVersion.agent_type == agent.agent_type,
            )
            .order_by(SecurityPolicyVersion.published_at.desc(), SecurityPolicyVersion.id.desc())
            .limit(1)
        )
        if policy is None:
            raise HTTPException(status_code=404, detail="No security policy has been published")
        return policy
