# Bound reviews and manual fulfillment: local implementation

The user approved P05's auth/model/migration design on 8 September 2026.
P06 and the initial P07 manual-removal workflow are implemented for local
validation. This is not production activation or a claim that Release A is ready.

## What changed

- New `bound-review-v2` cases snapshot the target's person binding. Assignment
  snapshots both target and reviewer bindings; decisions recheck and copy those
  bindings into immutable evidence. Link confirmation, revocation, expiry or changed
  account authority invalidates an earlier assignment. Two accounts linked to the
  same person cannot be assigned to review each other. Older bound cases without
  this evidence require cancellation and a fresh case; history is not backfilled.
  The existing cross-source non-retain approval guard remains in place.

- A tenant-scoped reviewer registry binds an active authoritative OIDC account to
  issuer and subject. Administrators register eligibility with a reason and can
  deactivate it. Actual reviewer role is checked again when acting. Names are labels.
- New reviews select one risk finding or policy evaluation, exact entitlement,
  proposed action and closure goal. The immutable snapshot contains source IDs,
  evidence version/time, opener identity and a target digest.
- Active-target uniqueness, revisions and row locks protect duplicate work and
  concurrent updates. Decisions require the bound owner, unchanged target and
  evidence from the last 24 hours. Cancellation permits fresh approval without
  replacing old evidence.
- Username-only HTTP mutation requests and CLI assignment/decision commands fail
  closed. Legacy histories remain readable. Internal legacy service routines are
  retained for synthetic scenarios and old evidence construction; they cannot
  mutate bound cases. The authenticated API uses the new service exclusively.
- Legacy approvals cannot create new execution requests through the API. Bound
  reviews also cannot enter the existing executor; manual fulfillment is required
  until a separately reviewed executor contract is implemented.
- Manual removal has a registered operator, due date, completion evidence and
  explicit verification events. Operator and approver must differ. Pending,
  overdue, awaiting-verification and recorded outcomes appear in the workspace.
- Completion and verification requests return HTTP 202 after persisting work.
  The worker collects approved read-only evidence and verifies stored results.
  Recollection must finish after operator completion.
  Failed/incomplete collection cannot advance that successful checkpoint.
- Exact Azure assignment removal checks every current grant carrying the source
  assignment ID, so a changed role action cannot masquerade as assignment removal.
  Continued access or insufficient coverage does not close the work; further
  assignment/completion attempts preserve prior attempts.
- Reviewers can prepare a case-scoped JSON evidence packet and digest, independently
  of administrator-only tenant reports.

## Starting a synthetic workflow

1. Review and apply migration `20260908_24` to a disposable PostgreSQL instance;
   run schema drift and tenant/RLS checks before using the new API against it.
2. An administrator registers authoritative OIDC accounts in reviewer eligibility
   administration, with the required identity-provider roles configured separately.
3. Select current risk/policy evidence, the proposed action and exact closure goal.
4. Assign an eligible reviewer. For revoke/extend/exception, the reviewer must be
   independent of the opener; self-review is prohibited.
5. After a revoke approval, assign an independent manual operator. The operator
   performs only the externally authorized action and records completion evidence.
6. Start the tenant worker described below. Recording completion queues collection
   and returns immediately. The workspace polls status and refreshes recorded
   outcomes. Inspect the actual outcome before reporting closure.

## Deliberate limits and outstanding acceptance

- No existing database was migrated. Only offline PostgreSQL SQL generation has
  succeeded; Docker remains unavailable. Migration application, schema drift,
  real PostgreSQL locking/RLS, Rego runtime and security-gate validation remain open.
- No connected browser was available. Signed-in registration, exact selection,
  assignment/decision conflicts, operator handoff, keyboard and visual acceptance
  still require the synthetic end-to-end exercise.
- Cross-source self-review identity binding remains unresolved until correlation
  work is implemented. Non-retain approval fails closed for targets outside the
  authoritative OIDC source. Synthetic service tests use explicit known bindings;
  they do not prove a real Azure/Keycloak identity correlation.
- GitHub calculated permissions cannot verify an underlying assignment's removal.
  A broad no-supported-paths goal stays insufficient coverage when no path is
  observed, because the collectors do not resolve all inheritance/deny semantics.
- The verified Azure outcome is relative to supported recorded collection, not an
  independent provider transaction snapshot. Collection failures are recorded in
  monitoring history with sanitized errors. Requests reuse completion/revision/hour
  schedule keys and existing leases; interrupted verification can reuse successful
  collection. A tenant-scoped CLI worker now retries pending completions with durable backoff
  and an automatic attempt limit; deployment and supervision remain outstanding.
  Collection no longer occupies the API request. Without a running worker,
  persisted work remains queued; accepting work does not prove worker availability.
- Extend and exception decisions record approved intent only. Time-bounded access
  fulfillment, expiration, exception lifecycle and campaigns remain later work.
- Registry and policy selectors currently load bounded pages (200 entries); the
  existing global loaded-page scope notice continues to apply.
- Production deployment, pilot ownership, cross-source correlation, requests,
  campaigns, executor activation and operational readiness are not completed.

## Observed validation

Full Python suite: 343 passed, 8 skipped, one existing Starlette/httpx warning.
Frontend: 12 tests passed; TypeScript/Vite build passed. Ruff and whitespace checks
passed. Targeted tests cover immutable-principal attribution, wrong/recycled
identity, ineligibility, self-review, revision conflicts, target changes, legacy
rejection, policy-only cases, cancellation, operator completion, insufficient
coverage and a still-present assignment after permission disappearance.

Recollection tests cover unapproved scopes never reaching the collector, failed
collection preserving completion, sanitized provider errors, replay after an
interrupted request, and automatic completion API wiring. No live collection was run.

## Background recovery worker

After configuring approved read-only connector scopes, a supervisor can run:

```powershell
python -m athena.cli retry-review-collection --tenant-id TENANT --interval-seconds 60
```

Omit `--interval-seconds` for a single sweep. `--limit` bounds attempted cases per
sweep (default 100, maximum 1000). The worker discovers persisted completions,
uses tenant-scoped keyset pages, and skips superseded assignments or recorded
outcomes other than collection-required. It never approves a review or performs
a provider access write. Verification events identify `urn:athena:internal-worker`
as the issuer and explicitly mark the actor as a service, not the human operator.

Failed attempts wait 60, 120, 240, then 480 seconds. The five-attempt automatic
budget includes collection attempts for the current completion or explicit
verification request and persists
across process restarts. Live leases defer work; expired runs reuse monitoring
lease recovery. A reviewer can request fresh verification after exhaustion; this
appends an event and starts a new budget without changing old evidence.
Counters report recorded verification requests, not proof of access removal.
Inspect the actual review outcome and monitoring history. Process supervision,
external exhaustion notifications and production load/concurrency validation
remain open. The workspace now displays retry exhaustion as an alert. No worker has been deployed
or run against live connector data during development.

## Asynchronous API and status

`POST /v1/reviews/{id}/fulfillment` returns 202 for completion (assignment still
returns 200). `POST /v1/reviews/{id}/verify` returns 202 after appending an explicit
verification request. Both retain revision checks and make no collector calls.
`GET /v1/reviews/{id}/collection-status` is tenant-scoped and reports state,
attempt count, budget, next retry time, and recorded outcome. States distinguish
not-requested, queued, running, retry-wait, exhausted, and completed processing.
Completed processing can mean still-present or insufficient coverage; it does
not imply verified removal. The workspace polls pending work every five seconds
and cancels polling when leaving the selected case. Failed status reads are
visible, and the prior recorded outcome cannot supersede a newer request.

Worker deployment configuration, heartbeat semantics and structured alert signals
are documented in [the worker runbook](review-worker-operations.md). Configuration
is prepared; actual deployment and external notification delivery remain open.
