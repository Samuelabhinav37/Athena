import os

import pytest
from athena.models import TenantScopedMixin
from sqlalchemy import event
from sqlalchemy.orm import Session

os.environ.setdefault("ATHENA_AUTH_REQUIRED", "false")


@pytest.fixture(autouse=True)
def test_tenant_context():
    def assign_test_tenant(session: Session, *_: object) -> None:
        for instance in session.new:
            if isinstance(instance, TenantScopedMixin) and instance.tenant_id is None:
                instance.tenant_id = "test-tenant"

    event.listen(Session, "before_flush", assign_test_tenant)
    try:
        yield
    finally:
        event.remove(Session, "before_flush", assign_test_tenant)
