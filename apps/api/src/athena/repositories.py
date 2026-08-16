import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import Identity


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self, *, limit: int, offset: int) -> list[Identity]:
        statement = select(Identity).order_by(Identity.username).limit(limit).offset(offset)
        return list(self.session.scalars(statement).unique())

    def get(self, identity_id: uuid.UUID) -> Identity | None:
        return self.session.get(Identity, identity_id)
