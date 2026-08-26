import uuid

from sqlalchemy.orm import Session

from athena.models import Identity
from athena.tenant_queries import tenant_select


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self, *, limit: int, offset: int) -> list[Identity]:
        statement = (
            tenant_select(self.session, Identity)
            .order_by(Identity.username)
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(statement).unique())

    def get(self, identity_id: uuid.UUID) -> Identity | None:
        statement = tenant_select(self.session, Identity, Identity.id == identity_id)
        return self.session.scalar(statement)

    def get_by_username(self, username: str) -> Identity | None:
        statement = tenant_select(self.session, Identity, Identity.username == username)
        return self.session.scalar(statement)
