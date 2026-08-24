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


def test_sync_does_not_reuse_records_from_another_tenant() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
        info={"tenant_id": "test-tenant"},
    )

    with factory() as session:
        tenant_a_identity = Identity(
            tenant_id="tenant-a",
            source="keycloak",
            external_id="user-alice",
            username="tenant-a-alice",
            identity_type=IdentityType.HUMAN,
            display_name="Tenant A Alice",
        )
        session.add_all([
            tenant_a_identity,
            Group(
                tenant_id="tenant-a",
                source="keycloak",
                external_id="group-engineering",
                name="Tenant A Engineering",
                path="/tenant-a/engineering",
            ),
            Role(
                tenant_id="tenant-a",
                source="keycloak",
                external_id="role-developer",
                name="Tenant A Developer",
            ),
        ])
        session.commit()

        result = IdentitySyncService(session).sync([alice_record()])

        tenant_b_identity = session.scalar(
            select(Identity).where(
                Identity.tenant_id == "test-tenant",
                Identity.external_id == "user-alice",
            )
        )
        assert result.identities_created == 1
        assert tenant_b_identity is not None
        assert tenant_b_identity.username == "alice"
        assert tenant_a_identity.username == "tenant-a-alice"
        assert [group.tenant_id for group in tenant_b_identity.groups] == ["test-tenant"]
        assert [role.tenant_id for role in tenant_b_identity.roles] == ["test-tenant"]

    engine.dispose()
