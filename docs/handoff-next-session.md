# Athena handoff

## 10 September validation follow-up

Continued the existing uncommitted person-link PostgreSQL acceptance tests and
tenant-transition preservation update. The preservation list now includes persons
and person_link_events. Database tests cover tenant visibility, immutable evidence
updates/deletes, allowed projection updates, unique current links and row locking.
Connection preflight requires PostgreSQL, the same database endpoint, and separate
owner/athena_app roles. Rejection assertions check specific PostgreSQL error codes
and the current-account unique constraint to avoid passing on unrelated errors.

Observed: backend suite 373 passed, 16 skipped; frontend 15 passed and production
build passed. Changed Python files pass Ruff. After tightening database error
assertions, focused tests reported 3 passed, 8 skipped. PostgreSQL tests remain
unexecuted: Docker's Linux engine pipe is unavailable. No database was migrated.
Security-gate execution failed because local OPA at 127.0.0.1:8181 was unreachable;
Rego runtime tests and schema-drift checks remain pending, as does signed-in browser
acceptance. These results do not establish release readiness. Changes are uncommitted.

The historical notes below include superseded next steps: commit 39804a3 already
contains manual person/account selection, and 3aafc17 contains review bindings.
Resume with disposable PostgreSQL and browser validation, not reimplementation.

Latest commit/push: 3aafc17 includes versioned person bindings in reviews. The
fourteenth slice is local: manual person/account selection uses two paginated
inventories and the existing two-steward form, allowing nonmatching contact hints.
Frontend validation: 15 tests and production build passed. No backend or migration
change. Browser acceptance and infrastructure release checks remain open.

Latest: work through the person-link pilot was pushed as 7212fbc. The thirteenth
slice is local: bound-review-v2 captures target person attribution and assignment
captures target/reviewer link revisions. Approval rejects corrections, expiry and
same-person reviews without rewriting history. Cross-source non-retain approval
remains blocked. Next: PostgreSQL/browser acceptance and a separately verified
authorization/execution boundary; do not remove guards on the strength of unit
tests alone. Full suite: 371 passed, 8 skipped; final focused tests: 43 passed;
Ruff passed. No frontend change or migration was added in this slice.

9 September: the user approved Keycloak as the synthetic pilot's person anchor
with two-steward confirmation. Person/link models, stewardship API/UI, immutable
history and forward migration 20260909_25 are implemented locally. Production
stewardship is blocked and links remain unusable for access approvals. The existing
cross-source approval rejection remains intact.

Full suite: 365 passed, 8 skipped. Final person-link/migration tests: 14 passed,
including subsequently added expiry and anchor-separation tests. Ruff, 12 frontend
tests, TypeScript/Vite build and offline PostgreSQL migration SQL generation passed.
No existing database was migrated. Real PostgreSQL/RLS/concurrency, Rego/security
gate and signed-in browser checks remain open.

Updated after the twelfth implementation slice on 9 September 2026.

## Resume here

Continue on `feat/analyst-command-center` with **release validation and P07 follow-ups**
from [the implementation plan](athena-implementation-plan.md).
Read AGENTS.md and inspect the working tree before making changes.

P00–P02 repaired the baseline and added versioned activity evidence quality.
P03 implemented tenant-scoped identity search and pagination, stable ordering,
matching counts, cancellation/error handling, and review handoff for identities
beyond the initial page. See [the inventory contract](identity-inventory.md) and
[the activity contract](activity-evidence-contract.md).

P04 added trusted and bounded pagination, organization-scoped GitHub absence
detection, Azure assignment validation before projection writes, and overlap tests.
Read [conformance limits](connector-conformance.md) and the concrete
[P05 design](review-target-owner-design.md). The user approved it; no repeated
approval is needed for the approved implementation. P06 and the initial manual
P07 workflow are implemented. See [operations and limits](bound-review-operations.md).
Keep credentials read-only and use synthetic fixtures. Work through the eighth
slice was committed and pushed as 79f7a16 on feat/analyst-command-center.
The ninth slice (candidate inspection and correlation design) remains local.

Next: validate migration 20260908_24, drift, RLS/concurrency and security gate on
disposable PostgreSQL when Docker is available; perform signed-in browser
acceptance when connected. Asynchronous collection and CLI recovery are implemented. Next address worker
deployment, external alerts and
remaining collection/correlation contracts. Cross-source destructive approval
currently fails closed because authoritative self-review binding is unresolved.
Do not claim Release A complete or enable the existing executor for these cases.

## Last observed verification

- Python: 351 passed, 8 skipped; one existing Starlette/httpx deprecation warning.
- Final correlation suite: 9 passed, including the subsequently added API boundary test.
- Frontend (unchanged this slice): 12 tests and TypeScript/Vite build passed.
- Offline PostgreSQL SQL generation passed; final targeted migration/target tests passed.
- Ruff and diff whitespace checks passed.
- Docker Linux engine unavailable: real PostgreSQL/migration/schema-drift,
  Rego runtime, and live security-gate checks remain open.
- No connected browser: signed-in keyboard, visual, and review-handoff acceptance
  remains pending. Follow the inventory acceptance checklist when available.

The work is locally validated, not production-ready. No live database migrations,
upstream access changes, new dependencies, or deployments were performed.
Research and walkthrough HTML files are in docs alongside the implementation plan.
This handoff records the stopping point; it does not schedule an automatic run.

## Current collection contract

Completion and explicit verification requests persist events and return HTTP 202;
they no longer call collectors. The retry-review-collection CLI consumes these
events; --interval-seconds 60 runs continuous sweeps. Collection is read-only,
tenant-scoped, lease-protected and backed off, with five attempts per work item.
Explicit reviewer requests reset the budget by creating a new immutable event.
The workspace polls collection-status and exposes exhaustion. No live worker was
launched. Worker supervision, external notifications, cross-source correlation and
release validation remain open. See bound-review-operations.md for commands and
API details. No schema or dependency change was added in this slice.

## Worker operations artifacts

compose.review-worker.yaml is an opt-in overlay for compose.demo.yaml. The CLI
--heartbeat-file flag supports container health checks; structured sweep events
include exhausted/failed counts, scan_complete and fixed alert codes. Review
review-worker-operations.md before deployment. Compose config --quiet passed with
synthetic values and no env file. No receiver is configured, no messages were sent,
and no image build or deployment occurred. Runtime drills and real alert delivery
remain open; code changes remain uncommitted.

## Next correlation work

The person-directory decision below is now resolved for the synthetic pilot.
Next: validate migration 20260909_25 on disposable PostgreSQL, run the two-steward
browser exercise, and design review snapshots that bind person-link revisions.
Do not remove the cross-source approval guard merely because links can be confirmed.
The manual account-pair selector for nonmatching contact hints remains a UI follow-up.

Read identity-correlation-design.md and CONTEXT.md. The read-only candidate endpoint
is implemented and tested; email hints never confirm links, merge accounts, or
relax approval checks. Person/link persistence and confirmation remain proposed.
Choose the authoritative person directory and independent confirmation evidence
before implementing that model. The candidate UI is implemented; signed-in visual/keyboard acceptance is pending. No new
migration, dependency, or live write was added in the ninth slice.

The tenth slice adds IdentityCorrelation.tsx to identity evidence. It displays
candidate reasons, inactive and ambiguous states, limits, retry, and account
navigation. It cancels abandoned requests and offers no link-confirmation action.
Frontend: 12 existing tests and production build passed. Browser list remains
empty, so visual/keyboard validation was not performed. Changes remain local.
