# Microsoft Entra ID and Azure RBAC connector

Athena inventories Microsoft Entra identities and Azure role-based access-control evidence without
changing Azure. Authentication uses `DefaultAzureCredential`; tokens are held in memory and are
never persisted in Athena evidence.

## Read-only access

Grant the collector application only the Microsoft Graph application permissions required for the
configured inventory:

- `User.Read.All` for users;
- `GroupMember.Read.All` for groups and membership; and
- `Application.Read.All` for service principals, managed identities, owners, and credential
  expiration metadata.

At the target subscription, assign a read-only Azure role that includes
`Microsoft.Authorization/roleAssignments/read` and
`Microsoft.Authorization/roleDefinitions/read`. Do not grant role-assignment write or delete
permissions to the collector.

## Configuration

`DefaultAzureCredential` supports environment credentials, workload identity, managed identity,
Azure CLI, and approved local developer credentials. Athena requires explicit tenant and
subscription scope:

```dotenv
ATHENA_AZURE_ENABLED=true
ATHENA_AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
ATHENA_AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
```

Run a read-only synchronization:

```bash
python -m athena.cli sync-azure
```

## Collected evidence

- Entra users, groups, memberships, service principals, and managed identities;
- service-principal owners and credential expiration times without key IDs or secret material;
- Azure RBAC assignments, role definitions, actions, scopes, and assignment conditions;
- canonical identities, resources, permissions, grants, and ordered provenance;
- unchanged-snapshot detection, removed-assignment detection, and audit events; and
- bounded connector status containing counts and a fingerprint rather than source payloads.

Every pagination link is restricted to its configured Microsoft Graph or Azure Resource Manager
origin. External content cannot redirect the collector to another host.

## Authorization limitations

The initial inventory is evidence, not a definitive Azure authorization simulation. It does not yet
resolve deny assignments, management-group inheritance, Privileged Identity Management activation,
custom security attributes, entitlement-management packages, or resource-specific data-plane
authorization. Those limitations remain attached to derived grants. OPA decisions and human review
remain separate from Azure collection.
