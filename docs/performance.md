# Athena performance and capacity guide

Athena keeps authorization evidence in PostgreSQL and treats analytics and graph data as
derived, advisory views. Capacity testing must use production-like tenant sizes before worker,
database, or container limits are raised.

## Implemented bounds

- Identity, machine identity, review, monitoring, execution, connector, entitlement, policy,
  risk, and anomaly list APIs enforce server-side limits.
- Machine posture batches page-level evidence queries instead of querying once per identity.
- GitHub collection lists collaborators once per repository rather than once per
  repository/member pair.
- Isolation Forest models are cached by tenant and cohort features in a bounded eight-entry
  process cache. Every analysis still records a new immutable evidence run.
- Scikit-learn and Neo4j load only when their optional features run.
- Signed-webhook replay protection is bounded and uses a heap for expiry cleanup.
- Versioned evidence APIs emit `Cache-Control: no-store`; sensitive tenant evidence must not be
  cached by browsers or shared proxies.

## Local resource ceilings

`compose.yaml` applies configurable CPU and memory ceilings to PostgreSQL, Keycloak, OPA, and
Neo4j. Override the `ATHENA_*_MEMORY_LIMIT` and `ATHENA_*_CPU_LIMIT` values only after observing
peak synchronization, policy, and graph workloads. Container ceilings are safety rails, not a
substitute for production orchestration limits and alerts.

## Measurements

Run the following from the repository root after changing dependencies or import boundaries:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check apps tests
Set-Location apps\web
npm run typecheck
npm run build
```

Measure database query plans against PostgreSQL with production-like data. In particular, inspect
tenant-filtered ordering for review history, monitoring history, effective entitlements, risk
assessments, and anomaly results. Adding or changing indexes requires an reviewed Alembic
migration; never alter the evidence database ad hoc.

## Remaining scale work

- Microsoft Graph and Azure Resource Manager collection still performs full snapshots because
  the connector does not yet implement provider delta cursors.
- Multi-page GitHub collections are deliberately refetched to avoid trusting a first-page ETag
  for later pages.
- Frontend list APIs use bounded offset pagination. Large tenants should add cursor-based UI
  navigation rather than increasing maximum page sizes.
- Benchmark live container memory and CPU with Docker running; static limits alone do not prove
  production capacity.
