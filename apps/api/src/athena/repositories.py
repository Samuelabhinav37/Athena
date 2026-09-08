import uuid

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from athena.models import Identity
from athena.tenant_queries import tenant_select


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _inventory_query(self, query: str) -> Select[tuple[Identity]]:
        statement = tenant_select(self.session, Identity)
        if query.strip():
            statement = statement.where(or_(
                *(field.icontains(query.strip(), autoescape=True) for field in (
                    Identity.username, Identity.display_name, Identity.email,
                    Identity.department, Identity.source, Identity.external_id,
                ))
            ))
        return statement

    def count(self, *, query: str = "") -> int:
        statement = select(func.count()).select_from(self._inventory_query(query).subquery())
        return self.session.scalar(statement) or 0

    def page(self, *, limit: int, offset: int, query: str) -> tuple[list[Identity], int]:
        # A window count keeps each nonempty page and its total in one database snapshot.
        rows = self.session.execute(
            self._inventory_query(query).add_columns(func.count().over())
            .order_by(Identity.username, Identity.id).limit(limit).offset(offset)
        ).unique().all()
        if not rows:
            return [], self.count(query=query)
        return [identity for identity, _ in rows], rows[0][1]

    def list(self, *, limit: int, offset: int, query: str = "") -> list[Identity]:
        statement = (
            self._inventory_query(query)
            .order_by(Identity.username, Identity.id)
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
