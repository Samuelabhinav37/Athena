# Tenant-isolation contract and threat model

Athena is currently a single-tenant application. Azure tenant IDs, GitHub organizations, Keycloak
realms, connector scopes, and identity sources are collected evidence—not an Athena authorization
boundary. No current API, database row, background job, cache, graph projection, or report should
be represented as safely tenant-isolated.

Contract `1.0` defines the target as shared-database row isolation. A canonical lowercase Athena
tenant ID must come from a validated context bound to an approved identity issuer or internal
service identity. Every persisted business/evidence row and every scoped reference must carry that
key. There is no global-administrator bypass. `require_tenant_access` demonstrates the default-deny
comparison rule but is not yet integrated into runtime data access.

## Trust boundaries

- The token verifier must bind the configured issuer, audience, subject, and dedicated
  `athena_tenant_id` claim. Request headers, query parameters, routes, and connector payloads cannot
  select or override a tenant.
- Background jobs must receive a validated tenant context in their durable schedule identity; no
  ambient process default may select a tenant.
- Database sessions must set transaction-local tenant context and enforce row-level security even
  if an application query omits its filter. Connection-pool reuse must clear or replace context.
- Object stores, caches, artifact names, idempotency keys, rate limits, graph projections, telemetry,
  backups, and restore operations must include and independently authorize the tenant boundary.
- Provider tenant IDs remain provenance. An administrator explicitly maps provider scopes to one
  Athena tenant; provider data cannot create or switch platform tenants.

## Threats and required mitigations

| Threat | Required mitigation |
|---|---|
| Missing tenant filter or unsafe join | Non-null tenant keys, composite foreign keys, RLS, negative SQL/ORM tests |
| Forged tenant header or token claim | Ignore headers; validate claim with issuer/audience and approved membership |
| Privileged cross-tenant access | No role bypass; separately authorized support workflow with immutable evidence |
| Connection-pool context leakage | Transaction-local context, fail closed when unset, reset tests across reused connections |
| Cache, job, or idempotency collision | Tenant-prefixed keys plus tenant ownership validation on retrieval/replay |
| Connector scope confusion | Explicit tenant-to-provider-scope mapping; source IDs never confer Athena authority |
| Export, logs, or error leakage | Tenant-scoped selection and destinations; redaction; no foreign identifiers in errors |
| Graph edge crossing tenants | Tenant-partitioned projection and edge constraints; cross-tenant path fixtures |
| Backup or residency violation | Tenant-aware encryption, retention, restore authorization, and region policy |

## Migration preconditions

The `TENANT_ISOLATION_PLAN` enumerates the affected entity families and blockers. Implementation
requires a reviewed, non-destructive migration sequence: introduce nullable keys; assign every
existing row to an explicitly approved bootstrap tenant; validate referential consistency; replace
unique and foreign-key constraints with tenant-aware forms; add and test RLS; then enforce non-null
keys. No guessed backfill is permitted.

Authentication and database changes are deliberately absent from this phase. Production tenancy
must not be enabled until API, ORM, direct SQL, background jobs, exports, Neo4j projections,
connectors, caches, backup/restore, and residency controls all pass cross-tenant denial tests.
