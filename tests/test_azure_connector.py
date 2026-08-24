from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
from athena.collectors.azure import AzureCollectionError, AzureCollector, AzureSnapshot
from athena.config import Settings
from athena.models import (
    AccessGrant,
    Base,
    ConnectorCheckpoint,
    EffectiveEntitlement,
    GrantSubjectType,
    Identity,
    IdentityType,
    Permission,
    Resource,
    ResourceType,
    Sensitivity,
)
from athena.services.azure_sync import AzureSyncService
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


class FakeCredential:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    def get_token(self, scope: str) -> SimpleNamespace:
        self.scopes.append(scope)
        return SimpleNamespace(token=f"token-{len(self.scopes)}")


def test_collector_paginates_only_trusted_azure_endpoints_and_excludes_secrets() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path == "/v1.0/users" and "page=2" not in request.url.query.decode():
            return httpx.Response(
                200,
                json={
                    "value": [{"id": "user-1", "userPrincipalName": "alice@example.test"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2",
                },
            )
        if path == "/v1.0/users":
            return httpx.Response(200, json={"value": []})
        if path == "/v1.0/groups":
            return httpx.Response(200, json={"value": [{"id": "group-1", "displayName": "Ops"}]})
        if path == "/v1.0/groups/group-1/members":
            return httpx.Response(200, json={"value": [{"id": "user-1"}]})
        if path == "/v1.0/servicePrincipals":
            return httpx.Response(
                200,
                json={
                    "value": [{
                        "id": "sp-1",
                        "appId": "app-1",
                        "displayName": "Deployer",
                        "servicePrincipalType": "Application",
                        "passwordCredentials": [{
                            "keyId": "must-not-be-normalized",
                            "secretText": "must-not-be-returned",
                            "endDateTime": "2026-09-01T00:00:00Z",
                        }],
                        "keyCredentials": [],
                    }]
                },
            )
        if path == "/v1.0/servicePrincipals/sp-1/owners":
            return httpx.Response(
                200,
                json={"value": [{"id": "user-1", "userPrincipalName": "alice@example.test"}]},
            )
        if path.endswith("/roleAssignments"):
            return httpx.Response(200, json={"value": []})
        if path.endswith("/roleDefinitions"):
            return httpx.Response(200, json={"value": []})
        raise AssertionError(f"Unexpected request: {request.url}")

    credential = FakeCredential()
    settings = Settings(
        database_url="sqlite://",
        azure_tenant_id="tenant-1",
        azure_subscription_id="subscription-1",
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        snapshot = AzureCollector(settings, credential, client).collect()

    assert credential.scopes == [
        "https://graph.microsoft.com/.default",
        "https://management.azure.com/.default",
    ]
    assert len(requests) == 8
    assert snapshot.group_members == {"group-1": ["user-1"]}
    assert (
        snapshot.service_principals[0]["AthenaOwners"][0]["userPrincipalName"]
        == "alice@example.test"
    )
    assert len(snapshot.fingerprint) == 64


def test_collector_rejects_pagination_to_an_untrusted_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1.0/users":
            return httpx.Response(
                200,
                json={"value": [], "@odata.nextLink": "https://attacker.example/collect"},
            )
        return httpx.Response(200, json={"value": []})

    settings = Settings(
        database_url="sqlite://",
        azure_tenant_id="tenant-1",
        azure_subscription_id="subscription-1",
    )
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        collector = AzureCollector(settings, FakeCredential(), client)
        try:
            collector.collect()
        except AzureCollectionError as error:
            assert "trusted API" in str(error.__cause__ or error)
        else:
            raise AssertionError("Untrusted pagination was accepted")


def snapshot(fingerprint: str, assignments: bool = True) -> AzureSnapshot:
    assignment_list = [
        {
            "id": (
                "/subscriptions/subscription-1/providers/"
                "Microsoft.Authorization/roleAssignments/assignment-1"
            ),
            "properties": {
                "principalId": "sp-1",
                "principalType": "ServicePrincipal",
                "roleDefinitionId": (
                    "/subscriptions/subscription-1/providers/"
                    "Microsoft.Authorization/roleDefinitions/role-1"
                ),
                "scope": "/subscriptions/subscription-1",
                "condition": None,
            },
        }
    ] if assignments else []
    return AzureSnapshot(
        tenant_id="tenant-1",
        subscription_id="subscription-1",
        users=[{
            "id": "user-1",
            "userPrincipalName": "alice@example.test",
            "displayName": "Alice",
            "accountEnabled": True,
        }],
        groups=[{"id": "group-1", "displayName": "Operations"}],
        group_members={"group-1": ["user-1"]},
        service_principals=[{
            "id": "sp-1",
            "appId": "app-1",
            "displayName": "Deployer",
            "servicePrincipalType": "ManagedIdentity",
            "accountEnabled": True,
            "AthenaOwners": [{"userPrincipalName": "alice@example.test"}],
            "passwordCredentials": [{
                "keyId": "excluded-key-id",
                "endDateTime": (datetime.now(UTC) + timedelta(days=15)).isoformat(),
            }],
            "keyCredentials": [],
        }],
        role_assignments=assignment_list,
        role_definitions=[{
            "id": (
                "/subscriptions/subscription-1/providers/"
                "Microsoft.Authorization/roleDefinitions/role-1"
            ),
            "properties": {
                "roleName": "Contributor",
                "permissions": [{
                    "actions": ["Microsoft.Compute/virtualMachines/read"],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                }],
            },
        }],
        endpoint_cache={"inventory": {"fingerprint": fingerprint}},
        fingerprint=fingerprint,
    )


def test_sync_materializes_azure_lineage_is_idempotent_and_revokes_removed_access() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with factory() as session:
        service = AzureSyncService(session)
        initial = snapshot("a" * 64)
        first = service.sync(initial)
        second = service.sync(initial)
        principal = session.scalar(
            select(Identity).where(Identity.source == "azure_entra", Identity.external_id == "sp-1")
        )
        grants = list(
            session.scalars(select(AccessGrant).where(AccessGrant.source == "azure_rbac"))
        )
        entitlements = list(
            session.scalars(
                select(EffectiveEntitlement).where(
                    EffectiveEntitlement.identity_id == principal.id
                )
            )
        )

        assert principal is not None
        assert principal.identity_type.value == "workload"
        assert principal.source_metadata["owner"] == "alice@example.test"
        assert principal.source_metadata["credential_expirations"]
        assert "excluded-key-id" not in str(principal.source_metadata)
        assert first.grants_created == 1
        assert second.unchanged is True
        assert len(grants) == 1
        assert len(entitlements) == 1
        assert all(grant.source_metadata["lineage_complete"] is False for grant in grants)

        removed = service.sync(snapshot("b" * 64, assignments=False))
        assert removed.grants_revoked == 1
        assert grants[0].revoked_at is not None
        assert entitlements[0].active is False

    engine.dispose()


def test_azure_checkpoint_cache_is_not_reused_across_tenants() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
        info={"tenant_id": "tenant-b"},
    )
    with factory() as session:
        session.add(
            ConnectorCheckpoint(
                tenant_id="tenant-a",
                connector="azure_rbac",
                scope="subscription-1",
                fingerprint="e" * 64,
                endpoint_cache={"inventory": {"etag": '"tenant-a"'}},
            )
        )
        session.commit()

        assert AzureSyncService(session).checkpoint("subscription-1") is None

    engine.dispose()


def test_azure_sync_does_not_deactivate_another_tenants_identity() -> None:
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
            source="azure_entra",
            external_id="tenant-a-only-user",
            username="tenant-a-user@example.test",
            identity_type=IdentityType.HUMAN,
            display_name="Tenant A User",
            active=True,
            source_metadata={"tenant_id": "tenant-1"},
        )
        session.add(tenant_a_identity)
        session.commit()

        AzureSyncService(session).sync(snapshot("c" * 64))

        assert tenant_a_identity.active is True

    engine.dispose()


def test_azure_sync_does_not_revoke_another_tenants_grant() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
        info={"tenant_id": "test-tenant"},
    )
    with factory() as session:
        identity = Identity(
            tenant_id="tenant-a",
            source="azure_entra",
            external_id="tenant-a-principal",
            username="tenant-a-principal",
            identity_type=IdentityType.APPLICATION,
            display_name="Tenant A Principal",
        )
        resource = Resource(
            tenant_id="tenant-a",
            source="azure_rbac",
            external_id="tenant-a-resource",
            name="Tenant A Resource",
            resource_type=ResourceType.CLOUD,
            sensitivity=Sensitivity.HIGH,
        )
        permission = Permission(
            tenant_id="tenant-a",
            resource=resource,
            action="Microsoft.Compute/virtualMachines/read",
            name="Tenant A Reader",
        )
        grant = AccessGrant(
            tenant_id="tenant-a",
            source="azure_rbac",
            external_id="tenant-a-grant",
            subject_type=GrantSubjectType.IDENTITY,
            identity=identity,
            permission=permission,
            granted_at=datetime.now(UTC),
            source_metadata={"subscription_id": "subscription-1"},
        )
        session.add(grant)
        session.commit()

        AzureSyncService(session).sync(snapshot("d" * 64, assignments=False))

        assert grant.revoked_at is None

    engine.dispose()
