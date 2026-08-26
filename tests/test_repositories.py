from athena.models import Base, Identity, IdentityType
from athena.repositories import IdentityRepository
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def test_identity_username_lookup_is_tenant_scoped() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, info={"tenant_id": "tenant-a"}) as session:
        session.add_all(
            [
                Identity(
                    tenant_id="tenant-a",
                    source="keycloak",
                    external_id="alice-a",
                    username="alice",
                    identity_type=IdentityType.HUMAN,
                    display_name="Alice A",
                ),
                Identity(
                    tenant_id="tenant-b",
                    source="keycloak",
                    external_id="alice-b",
                    username="alice",
                    identity_type=IdentityType.HUMAN,
                    display_name="Alice B",
                ),
            ]
        )
        session.commit()

        identity = IdentityRepository(session).get_by_username("alice")

        assert identity is not None
        assert identity.tenant_id == "tenant-a"

    engine.dispose()
