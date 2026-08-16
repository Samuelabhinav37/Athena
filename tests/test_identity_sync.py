from athena.collectors.contracts import NormalizedGroup, NormalizedIdentity, NormalizedRole
from athena.models import Base, Group, Identity, IdentityType, Role
from athena.services.identity_sync import IdentitySyncService
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker


def alice_record() -> NormalizedIdentity:
    return NormalizedIdentity(
        source="keycloak",
        external_id="user-alice",
        username="alice",
        identity_type=IdentityType.HUMAN,
        display_name="Alice Johnson",
        email="alice@acme.test",
        department="engineering",
        job_title="Developer",
        manager_external_id="bob",
        active=True,
        groups=[
            NormalizedGroup(
                external_id="group-engineering",
                name="engineering",
                path="/departments/engineering",
            )
        ],
        roles=[
            NormalizedRole(
                external_id="role-developer",
                name="developer",
                description="Application developer",
            )
        ],
    )


def test_sync_is_idempotent_and_updates_relationships() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with factory() as session:
        first = IdentitySyncService(session).sync([alice_record()])
        second = IdentitySyncService(session).sync([alice_record()])

        assert first.identities_created == 1
        assert first.identities_updated == 0
        assert second.identities_created == 0
        assert second.identities_updated == 1
        assert session.scalar(select(func.count()).select_from(Identity)) == 1
        assert session.scalar(select(func.count()).select_from(Group)) == 1
        assert session.scalar(select(func.count()).select_from(Role)) == 1

        alice = session.scalar(select(Identity).where(Identity.username == "alice"))
        assert alice is not None
        assert [group.name for group in alice.groups] == ["engineering"]
        assert [role.name for role in alice.roles] == ["developer"]
