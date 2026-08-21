import json

import pytest
from athena.models import Base, Identity, IdentityType
from athena.services.tenant_inventory import (
    TenantInventoryError,
    capture_tenant_inventory,
)
from athena.tenant_transition import TENANT_TABLES
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_inventory_counts_every_table_without_writing() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory.begin() as session:
        session.add(
            Identity(
                source="keycloak",
                external_id="alice",
                username="alice",
                identity_type=IdentityType.HUMAN,
                display_name="Alice",
                active=True,
            )
        )
    with factory() as session:
        first = capture_tenant_inventory(session)
        second = capture_tenant_inventory(session)
        identities = list(session.scalars(select(Identity)))

        assert set(first.table_counts) == set(TENANT_TABLES)
        assert first.table_counts["identities"] == 1
        assert first.total_rows == 1
        assert first.inventory_sha256 == second.inventory_sha256
        assert len(first.inventory_sha256) == 64
        assert identities[0].username == "alice"
        assert not session.new and not session.dirty and not session.deleted
    engine.dispose()


def test_inventory_rejects_session_with_pending_changes() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    with factory() as session:
        session.add(
            Identity(
                source="keycloak",
                external_id="pending",
                username="pending",
                identity_type=IdentityType.HUMAN,
                display_name="Pending",
                active=True,
            )
        )
        with pytest.raises(TenantInventoryError, match="no pending changes"):
            capture_tenant_inventory(session)
    engine.dispose()


def test_inventory_json_contains_counts_and_no_row_content() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        payload = json.loads(capture_tenant_inventory(session).model_dump_json())

    assert payload["table_counts"] == {table: 0 for table in TENANT_TABLES}
    assert "rows" not in payload
    assert "records" not in payload
    engine.dispose()
