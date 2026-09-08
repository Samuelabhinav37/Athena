# Analyst workflow baseline

Verified on 2026-09-06 against working-tree commit `7bd2234`.

## Observed checks

- Web production build (`npm run build`): passed, including TypeScript compilation.
- Python suite (`.venv/Scripts/python.exe -m pytest -q`): 281 passed, 8 skipped,
  one Starlette/httpx deprecation warning. Skipped checks are not passes.
- Existing demo stack: web, API, PostgreSQL, Keycloak, OPA and Neo4j containers
  reported healthy after Docker became available.
- Dashboard HTTP endpoint (`http://localhost:3000`): HTTP 200.
- Rego tests in the demo OPA container: 5/5 passed.
- Deterministic security gate: passed, four fixtures and three control mappings,
  zero failures. Executed in a temporary container using the existing API image,
  with this repository mounted read-only at `/workspace` and the demo OPA service.
  Its temporary report was not retained after container removal.

The existing demo images have not been rebuilt or proven identical to the current
working tree. Container health and HTTP 200 do not establish authenticated workflow
correctness. No production-readiness claim follows from these checks.

## First milestone: verify an analyst workflow

Pending: sign in through Keycloak, inspect the command center, select an identity,
trace its access evidence, inspect an investigation and its decision history, and
verify an evidence report against the source facts. Use controlled demonstration
data for any subsequent review writes; actual upstream access execution remains
outside this milestone.

Browser runtime initialization succeeded but discovery returned no connected
browsers. Authenticated UI verification remains blocked on a browser connection.
Fresh disposable PostgreSQL migration, schema-drift and isolation checks also remain
outstanding. No existing database was migrated or reset during this baseline.

## Delivery order

1. Finish the analyst workflow verification and fix demonstrated workflow gaps.
2. Assess existing request/review contracts, then implement the smallest complete
   access-request and approval slice with behavioral tests. Follow with staged
   approvals, expiration, recurring reviews and verified fulfillment individually.
3. Validate connector semantics and graph correctness with explicit expected-result
   fixtures for nested groups, inheritance and conditional/deny behavior.
4. Close production operational evidence in `governance/readiness.json`, beginning
   with deployment ownership and platform decisions, then recovery and observability.

Treat these as sequential milestones, not evidence that the capabilities are complete.
