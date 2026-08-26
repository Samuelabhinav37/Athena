import hashlib
import json
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import ConnectorScopeBinding, ConnectorScopeRevocation
from athena.tenancy import TENANT_ID_PATTERN


class ConnectorAdministrationError(RuntimeError):
    pass


class ConnectorScopeChangePlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    database_mutation: Literal[True] = True
    action: Literal["approve", "revoke"]
    tenant_id: str = Field(pattern=TENANT_ID_PATTERN)
    connector: str = Field(min_length=1, max_length=64)
    scope: str = Field(min_length=1, max_length=255)
    approval_reference: str = Field(min_length=1, max_length=255)
    authorized_by: str = Field(min_length=1, max_length=255)
    authorized_at: datetime
    reason: str | None = Field(default=None, min_length=1, max_length=4000)
    binding_id: uuid.UUID | None = None
    plan_sha256: str

    @model_validator(mode="after")
    def require_action_fields(self) -> "ConnectorScopeChangePlan":
        if self.action == "approve" and (self.reason is not None or self.binding_id is not None):
            raise ValueError("Approval plans cannot contain revocation fields")
        if self.action == "revoke" and (self.reason is None or self.binding_id is None):
            raise ValueError("Revocation plans require a binding and reason")
        return self


def _digest(facts: dict[str, object]) -> str:
    payload = json.dumps(
        facts, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _normalized(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not normalized:
        raise ConnectorAdministrationError(f"{label} is required")
    return normalized


class ConnectorAdministration:
    """Plan and apply connector-scope changes through one guarded interface."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def plan_approval(
        self,
        *,
        tenant_id: str,
        connector: str,
        scope: str,
        approval_reference: str,
        authorized_by: str,
        authorized_at: datetime,
    ) -> ConnectorScopeChangePlan:
        connector = _normalized(connector, "Connector")
        scope = _normalized(scope, "Scope")
        existing = self._binding(tenant_id, connector, scope)
        if existing is not None:
            raise ConnectorAdministrationError("Connector scope already has a binding")
        facts = {
            "schema_version": "1.0",
            "database_mutation": True,
            "action": "approve",
            "tenant_id": tenant_id,
            "connector": connector,
            "scope": scope,
            "approval_reference": approval_reference.strip(),
            "authorized_by": authorized_by.strip(),
            "authorized_at": authorized_at.isoformat(),
            "reason": None,
            "binding_id": None,
        }
        return ConnectorScopeChangePlan(**facts, plan_sha256=_digest(facts))

    def plan_revocation(
        self,
        *,
        tenant_id: str,
        connector: str,
        scope: str,
        approval_reference: str,
        authorized_by: str,
        authorized_at: datetime,
        reason: str,
    ) -> ConnectorScopeChangePlan:
        connector = _normalized(connector, "Connector")
        scope = _normalized(scope, "Scope")
        binding = self._binding(tenant_id, connector, scope)
        if binding is None:
            raise ConnectorAdministrationError("Connector scope binding does not exist")
        if self._revocation(tenant_id, binding.id) is not None:
            raise ConnectorAdministrationError("Connector scope binding is already revoked")
        facts = {
            "schema_version": "1.0",
            "database_mutation": True,
            "action": "revoke",
            "tenant_id": tenant_id,
            "connector": connector,
            "scope": scope,
            "approval_reference": approval_reference.strip(),
            "authorized_by": authorized_by.strip(),
            "authorized_at": authorized_at.isoformat(),
            "reason": reason.strip(),
            "binding_id": binding.id,
        }
        return ConnectorScopeChangePlan(**facts, plan_sha256=_digest(facts))

    def apply(
        self, plan: ConnectorScopeChangePlan, *, confirmed_plan_sha256: str
    ) -> ConnectorScopeBinding | ConnectorScopeRevocation:
        if confirmed_plan_sha256 != plan.plan_sha256:
            raise ConnectorAdministrationError("Confirmed plan digest does not match")
        if plan.action == "approve":
            if self._binding(plan.tenant_id, plan.connector, plan.scope) is not None:
                raise ConnectorAdministrationError("Connector scope changed after plan creation")
            result: ConnectorScopeBinding | ConnectorScopeRevocation = ConnectorScopeBinding(
                tenant_id=plan.tenant_id,
                connector=plan.connector,
                scope=plan.scope,
                approval_reference=plan.approval_reference,
                approved_by=plan.authorized_by,
                approved_at=plan.authorized_at,
            )
        else:
            binding = self._binding(plan.tenant_id, plan.connector, plan.scope)
            if binding is None or binding.id != plan.binding_id:
                raise ConnectorAdministrationError("Connector scope changed after plan creation")
            if self._revocation(plan.tenant_id, binding.id) is not None:
                raise ConnectorAdministrationError("Connector scope binding is already revoked")
            result = ConnectorScopeRevocation(
                tenant_id=plan.tenant_id,
                binding_id=binding.id,
                approval_reference=plan.approval_reference,
                revoked_by=plan.authorized_by,
                revoked_at=plan.authorized_at,
                reason=plan.reason or "",
            )
        self.session.add(result)
        self.session.flush()
        return result

    def _binding(
        self, tenant_id: str, connector: str, scope: str
    ) -> ConnectorScopeBinding | None:
        return self.session.scalar(
            select(ConnectorScopeBinding).where(
                ConnectorScopeBinding.tenant_id == tenant_id,
                ConnectorScopeBinding.connector == connector,
                ConnectorScopeBinding.scope == scope,
            )
        )

    def _revocation(
        self, tenant_id: str, binding_id: uuid.UUID
    ) -> ConnectorScopeRevocation | None:
        return self.session.scalar(
            select(ConnectorScopeRevocation).where(
                ConnectorScopeRevocation.tenant_id == tenant_id,
                ConnectorScopeRevocation.binding_id == binding_id,
            )
        )
