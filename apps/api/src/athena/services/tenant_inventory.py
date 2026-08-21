import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.models import Base
from athena.tenant_transition import TENANT_TABLES


class TenantInventoryError(RuntimeError):
    pass


class TenantInventorySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    observed_at: datetime
    table_counts: dict[str, int]
    total_rows: int
    inventory_sha256: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def capture_tenant_inventory(session: Session) -> TenantInventorySnapshot:
    if session.new or session.dirty or session.deleted:
        raise TenantInventoryError("Tenant inventory requires a session with no pending changes")
    model_tables = set(Base.metadata.tables)
    if model_tables != set(TENANT_TABLES):
        raise TenantInventoryError("Tenant transition table coverage does not match model metadata")

    counts = {}
    with session.no_autoflush:
        for table_name in TENANT_TABLES:
            table = Base.metadata.tables[table_name]
            counts[table_name] = int(
                session.scalar(select(func.count()).select_from(table)) or 0
            )
    facts = {
        "schema_version": "1.0",
        "table_counts": counts,
        "total_rows": sum(counts.values()),
    }
    return TenantInventorySnapshot(
        **facts,
        observed_at=datetime.now(UTC),
        inventory_sha256=hashlib.sha256(_canonical(facts)).hexdigest(),
    )
