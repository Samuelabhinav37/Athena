# Athena handoff

Updated after the eighth implementation slice on 8 September 2026.

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
Keep credentials read-only and use synthetic fixtures. P04 and this slice remain
uncommitted; the previous push ended at f5be4fb.

Next: validate migration 20260908_24, drift, RLS/concurrency and security gate on
disposable PostgreSQL when Docker is available; perform signed-in browser
acceptance when connected. Asynchronous collection and CLI recovery are implemented. Next address worker
deployment, external alerts and
remaining collection/correlation contracts. Cross-source destructive approval
currently fails closed because authoritative self-review binding is unresolved.
Do not claim Release A complete or enable the existing executor for these cases.

## Last observed verification

- Python: 343 passed, 8 skipped; one existing Starlette/httpx deprecation warning.
- Frontend: 12 tests and TypeScript/Vite build passed.
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
