from pydantic import BaseModel, Field

from athena.models import IdentityType


class NormalizedGroup(BaseModel):
    external_id: str
    name: str
    path: str


class NormalizedRole(BaseModel):
    external_id: str
    name: str
    description: str | None = None


class NormalizedIdentity(BaseModel):
    source: str
    external_id: str
    username: str
    identity_type: IdentityType
    display_name: str
    email: str | None = None
    department: str | None = None
    job_title: str | None = None
    manager_external_id: str | None = None
    active: bool
    source_metadata: dict = Field(default_factory=dict)
    groups: list[NormalizedGroup] = Field(default_factory=list)
    roles: list[NormalizedRole] = Field(default_factory=list)
