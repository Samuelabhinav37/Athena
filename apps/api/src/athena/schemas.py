import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from athena.models import IdentityType


class GroupSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    path: str


class RoleSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None


class IdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    external_id: str
    username: str
    identity_type: IdentityType
    display_name: str
    email: str | None
    department: str | None
    job_title: str | None
    manager_external_id: str | None
    active: bool
    observed_at: datetime
    groups: list[GroupSummary]
    roles: list[RoleSummary]
