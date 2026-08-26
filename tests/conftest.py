import os

import pytest
from athena.models import TenantScopedMixin
from sqlalchemy import event
from sqlalchemy.orm import Session

os.environ.setdefault("ATHENA_AUTH_REQUIRED", "false")
os.environ.setdefault("ATHENA_API_WORKER_COUNT", "1")
os.environ.setdefault("ATHENA_API_REPLICA_COUNT", "1")


@pytest.fixture(autouse=True)
def test_tenant_context():
    original_init = Session.__init__

    def initialize_test_session(session: Session, *args: object, **kwargs: object) -> None:
        info = kwargs.setdefault("info", {})
        if not isinstance(info, dict):
            raise TypeError("Session info must be a dictionary")
        if "administrative_scope" not in info:
            info.setdefault("tenant_id", "test-tenant")
        original_init(session, *args, **kwargs)

    def assign_test_tenant(session: Session, *_: object) -> None:
        for instance in session.new:
            if isinstance(instance, TenantScopedMixin) and instance.tenant_id is None:
                instance.tenant_id = "test-tenant"

    Session.__init__ = initialize_test_session  # type: ignore[method-assign]
    event.listen(Session, "before_flush", assign_test_tenant)
    try:
        yield
    finally:
        event.remove(Session, "before_flush", assign_test_tenant)
        Session.__init__ = original_init  # type: ignore[method-assign]
