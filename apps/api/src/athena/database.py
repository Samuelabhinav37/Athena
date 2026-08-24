from collections.abc import Generator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from athena.auth import get_tenant_context
from athena.config import get_settings
from athena.models import TenantScopedMixin
from athena.tenancy import TenantContext


@lru_cache
def get_engine() -> Engine:
    engine = create_engine(get_settings().database_url, pool_pre_ping=True)
    if engine.dialect.name == "postgresql":
        event.listen(engine, "connect", _assume_application_role)
    return engine


def _assume_application_role(dbapi_connection: object, _: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("SET ROLE athena_app")
    finally:
        cursor.close()


def get_session_factory(tenant_id: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_engine(),
        autoflush=False,
        expire_on_commit=False,
        info={"tenant_id": tenant_id},
    )


def get_system_session_factory() -> sessionmaker[Session]:
    return get_session_factory(get_settings().system_tenant_id)


def get_db_session(
    context: Annotated[TenantContext, Depends(get_tenant_context)],
) -> Generator[Session]:
    with get_session_factory(context.tenant_id)() as session:
        yield session


@event.listens_for(Session, "after_begin")
def _set_transaction_tenant(session: Session, _: object, connection: object) -> None:
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None or connection.dialect.name != "postgresql":  # type: ignore[attr-defined]
        return
    connection.execute(  # type: ignore[attr-defined]
        text("SELECT set_config('athena.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


@event.listens_for(Session, "before_flush")
def _assign_transaction_tenant(session: Session, *_: object) -> None:
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        return
    for instance in session.new:
        if isinstance(instance, TenantScopedMixin) and instance.tenant_id is None:
            instance.tenant_id = tenant_id
