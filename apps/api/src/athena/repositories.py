import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import Identity


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self, *, limit: int, offset: int) -> list[Identity]:
        statement = select(Identity).order_by(Identity.username).limit(limit).offset(offset)
        tenant_id = self.session.info.get("tenant_id")
        if tenant_id is not None:
            statement = statement.where(Identity.tenant_id == tenant_id)
        return list(self.session.scalars(statement).unique())

    def get(self, identity_id: uuid.UUID) -> Identity | None:
        statement = select(Identity).where(Identity.id == identity_id)
        tenant_id = self.session.info.get("tenant_id")
        if tenant_id is not None:
            statement = statement.where(Identity.tenant_id == tenant_id)
        return self.session.scalar(statement)
