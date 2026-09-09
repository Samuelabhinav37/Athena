# Athena implementation plan: from the first patch to production

Prepared 8 September 2026. Status: implementation started; P00–P03 locally validated, browser and infrastructure verification remain open. Basis: the current working tree, [security/product assessment](athena-security-product-research.md), [competitor mechanisms](athena-competitor-mechanisms-2026-09-08.md), and the canonical [readiness manifest](../governance/readiness.json).

## Fourteenth slice: manual account-pair selection

Pushed review-binding work as 3aafc17. Added two paginated account pickers so
stewards can propose exact account pairs without matching email hints. The pilot
requires an active human Keycloak anchor and a separate supported human account.
Existing evidence and two-steward requirements remain. Shared inventory instances
now have unique input IDs and contextual labels. Frontend: 15 tests and build
passed; signed-in browser acceptance is still pending. New work remains local.

## Thirteenth slice: versioned person bindings in review evidence

New bound-review-v2 cases capture target person attribution. Assignment records
target and reviewer bindings, including exact link revisions; approval rechecks
them and records the same evidence. Same-person assignment through different
accounts is rejected. Confirmation/revocation, expiry and authority changes
invalidate pending work. Existing cases without person bindings need fresh review.
No new migration or dependency. Cross-source approval and executor blocks remain.
Full suite: 371 passed, 8 skipped; lint passed. Final focused tests: 43 passed,
including expiry and target changes added after that full run.

## Twelfth slice: approved Keycloak person-link pilot

The user approved Keycloak anchors and two-steward documented confirmation.
Implemented person/link persistence, immutable event history, account-authority
snapshots, independent registered administrators, proposal freshness, 30-day
validity, rejection/revocation and account-link uniqueness. Added stewardship API
and candidate-pair UI. Migration 20260909_25 is additive/forward-only with forced
RLS and restricted runtime updates; only offline SQL generation has run.
Production stewardship is blocked and confirmed links cannot authorize access.
Full suite: 365 passed, 8 skipped; final focused tests: 14 passed; Ruff, frontend
tests/build and offline SQL generation passed. PostgreSQL/browser release gates
and person-link-version binding in access reviews remain next work.

## Eleventh slice: account-authority preflight

Azure ingestion now rejects duplicate account IDs and existing accounts with
missing/conflicting directory authority before identity writes or checkpoint
refresh. Regression tests preserve the previous projection for both changed and
unchanged fingerprints. Targeted Azure/correlation tests: 25 passed; Ruff passed.
Full regression suite: 357 passed, 8 skipped, one existing Starlette/httpx warning.
This is a sequential preflight, not the future scoped database account model.
The authoritative person directory remains a pending pilot decision.

## Tenth slice: candidate inspection workspace

Added the read-only candidate panel to identity evidence, with explicit ambiguity,
inactive account labels, bounded result expansion, failure/retry and navigation
to candidate account evidence. Abandoned requests are cancelled. No confirmation
or merge action exists. Frontend: 12 existing tests and TypeScript/Vite build
passed. Browser acceptance remains unavailable; see the correlation design checklist.

## Ninth slice: read-only correlation candidates and proposed link design

Work through slice eight was committed and pushed as 79f7a16. Added a tenant-scoped
candidate inspection endpoint using contact hints only, explicit ambiguity and
unsupported states, and bounded results. No link is confirmed and no source
account/history or approval rule changes. See identity-correlation-design.md for
the proposed persisted model and confirmation boundary; CONTEXT.md records terms.
Full Python suite: 351 passed, 8 skipped; final correlation suite: 9 passed after
adding the API tenant/limit test. Ruff passed. New correlation work remains local.

## Eighth slice: worker deployment configuration and operational signals

Added an opt-in Compose worker overlay using the existing non-root API image,
restricted runtime DB login, read-only filesystem, no published ports and heartbeat
health checking. CLI sweep logs now expose retry exhaustion, collection failures,
partial-scan semantics and sanitized service errors. The alert-routing runbook
specifies deduplication and resolution conditions without configuring a receiver.
Merged Compose configuration passed using synthetic values. Runtime deployment,
external alert delivery, correlation and infrastructure release gates remain open.

## Seventh slice: asynchronous collection and retry visibility

Completion and verification requests now persist work and return HTTP 202 without
provider calls. The worker consumes completion/request events. A tenant-scoped
status endpoint exposes queue, lease, retry timing, exhausted budget and outcome;
the workspace polls pending work and refreshes recorded results. Explicit retries
append evidence and begin a new budget. No schema or dependency change was needed.
Validation: 340 Python tests passed, 8 skipped; 12 frontend tests and build passed.
Deployment/supervision, external alerts, correlation and release gates remain open.

## Sixth slice: background recovery

Added a tenant-scoped CLI recovery worker with optional continuous operation,
durable backoff, five-attempt budget, existing lease recovery, and explicit service
attribution. It scans persisted completion records and stops after a recorded
provider outcome. Tests cover isolation, budgets, live leases and attribution.
Worker deployment/supervision, exhaustion alerts and fully asynchronous initial
collection remain open. See bound review operations for the command and limits.

## Fifth slice: request-driven recollection

Completion now triggers scope-approved Azure collection and verification. Failed
collection preserves completion and records a sanitized monitoring failure.
Existing schedule keys and leases support retry after interruption. The workspace
verification button recollects before checking evidence. This is synchronous request
processing; unattended recovery and background scheduling remain open. No new
dependency or migration was added. Validation: 333 Python tests passed, 8 skipped;
11 frontend tests, TypeScript/Vite build, Ruff and whitespace checks passed.
Infrastructure and browser release gates remain open.

## Fourth slice — Approved P05, P06 and initial P07 implementation

Implemented immutable reviewer registry bindings, exact risk/policy target
snapshots, revision/concurrency guards, eligibility checks, independent approval,
legacy mutation rejection and cancellation for fresh evidence. Added manual
operator assignment/completion, read-only verification from fresh recorded
checkpoints, correction retries, due/overdue display and case evidence packets.
Migration `20260908_24` is additive and forward-only; no existing database was
migrated. Offline PostgreSQL SQL generation succeeds.

Validation: **329 Python tests passed, 8 skipped**; **11 frontend tests passed**;
Ruff and TypeScript/Vite build passed. Final target-immutability/migration tests
also passed. No connected browser or Docker engine was available, so real
PostgreSQL/RLS/concurrency, migration/drift, Rego/security gate and signed-in
acceptance remain outstanding. These are release gates, not waived checks.

See [bound review operations](bound-review-operations.md) for the exact implemented
scope. P07 now triggers approved read-only Azure recollection and verification
after completion, with durable monitoring attempts and explicit retry. A CLI worker provides unattended
recovery and backoff when deployed; deployment remains outstanding. Cross-source
self-review binding fails closed until correlation is implemented, and broader
effective-access closure cannot be certified with incomplete provider semantics.
Release A is therefore not yet complete. Later correlation, lifecycle/campaigns,
controlled execution and production readiness remain work in the delivery map.
This slice has not been committed or pushed.

## Third slice — P04 conformance and P05 design

Implemented trusted-endpoint and bounded pagination checks, GitHub organization-
scoped removal detection, and Azure preflight rejection of unresolved assignments,
conditions and exclusions. Azure records source assignment IDs for future target
binding. Synthetic tests cover empty continuation pages, late failures, malformed
responses, cycles, organization boundaries and overlapping direct/group paths.

Full Python validation: **313 passed, 8 skipped**, with the existing deprecation
warning; Ruff passed. No frontend code changed in this slice. Docker/runtime and
signed-in browser acceptance remain open. See [P04 conformance](connector-conformance.md)
for the supported subset and remaining phase-3 collection work; P04 does not mean
all collection semantics or production readiness are complete.

[P05 review-owner and target proposal](review-target-owner-design.md) is prepared
for the plan's explicit auth/model/migration review gate. It specifies immutable
reviewer bindings, legacy-owner handling, exact evidence targets, concurrency and
the P07 fulfillment seam. P06/P07 implementation, broader lifecycle/correlation,
controlled execution and operational readiness remain outstanding. No migration,
authentication change, live access change, commit or push occurred in this slice.

## Second slice — P03 inventory navigation

Implemented tenant-scoped server search and a paged identity response, preserving
the existing list API. The dashboard now searches all stored tenant accounts,
displays matching counts, and supports 50-record pages with Previous, Next, and
First page controls. Stable username/ID ordering handles duplicate usernames.
Selection stays explicit across pages, and accounts outside the initial loaded
page carry through to review creation. Cancellation and error states prevent old
responses or failed requests from appearing as current empty results.

Validation: **296 Python tests passed, 8 skipped**, with the existing deprecation
warning; **9 frontend tests passed**; Ruff, TypeScript/Vite build, and diff checks
passed. Tests include 205 accounts, search beyond the original page, duplicates,
literal search characters, bounds, and tenant-scoped counts, plus cancelled
requests and error propagation. Browser discovery returned no connected browser;
keyboard, visual, and signed-in review-handoff acceptance remain pending. Docker
Linux engine remains unavailable, so infrastructure checks are still open.

See [inventory contract and acceptance checklist](identity-inventory.md). Next:
P04 connector conformance baseline. No dependencies, schema migrations, live
access changes, deployments, commits, or pushes were performed in this slice.

## Implementation progress — 8 September 2026

- P00: reproduced and repaired the connector lint error and outdated dashboard
  setup assertions. Assertions now check current source setup, credential handling,
  read-only collection, and the decision-versus-upstream-change boundary.
- P01: recorded the [activity evidence contract](activity-evidence-contract.md),
  including explicit uncertainty scoring, freshness thresholds, examples, and limits.
- P02: new `access-decay-v2` assessments distinguish recent, stale, unknown, and
  invalid activity. Missing or outdated evidence retains a 15-point uncertainty
  reserve and cannot create a stale-access classification or measured-age reason.
  API factors include evidence references and treatment; the dashboard displays
  stored explanations and model version. Historical assessments remain unchanged.
- Verification: full pytest run **291 passed, 8 skipped**, with one existing
  Starlette/httpx deprecation warning; Ruff passed; frontend **5 tests passed**;
  TypeScript/Vite production build passed. Regression coverage includes API output,
  unknown activity, invalid timestamp ordering, outdated observations, measured
  age, and preservation of prior assessment versions.
- Remaining verification: Docker Linux engine unavailable. Real PostgreSQL,
  migrations/schema drift, Rego runtime tests, and live security-gate validation
  remain open. Authenticated visual browser verification was not performed.
  These local results do not establish production readiness.
- At this first-slice checkpoint, the next patch was P03 (implemented above). Later phases
  retain their order and acceptance gates. No deployment, live database migration,
  upstream access change, dependency change, commit, or push was performed.

## Outcome and initial scope

Deliver this first: **an administrator connects a read-only source, an analyst finds an evidence-backed access issue, an eligible reviewer decides what to do, a named person performs any authorized correction, and Athena records what a fresh observation establishes.**

Initial users: a small security/IT team, resource owners, and an administrator exporting evidence. This audience is a working hypothesis to validate with a pilot. Initial providers: GitHub and Entra/Azure, restricted to explicitly supported semantics. Use Keycloak and synthetic provider fixtures for local development. Machine identities are included where current source coverage supports them; they are not assumed equivalent to human users.

Avoid a big rewrite. Extend the existing collectors, PostgreSQL evidence model, OPA evaluation, review workspace, monitoring, and reporting. Keep Neo4j and AI optional for the first useful workflow. This plan adopts mechanisms learned from competitors; it does not select a vendor dependency or authorize importing a connector SDK.

## Boundaries throughout the work

- OPA remains the policy authority. ML recommends and AI explains; neither can authorize execution.
- Existing collector credentials stay read-only. Any later write adapter has its own separately authorized credential and runtime boundary.
- Evidence and historical decisions remain append-only. New assessments and corrected identity links retain prior versions.
- Tenant scope applies to API requests, jobs, caches, graph data, exports, and connector state.
- Approval, execution response, and observed outcome remain distinct. An exception or expired request is not automatically an upstream change.
- Research and this plan do not authorize live access changes, production deployment, infrastructure spending, or a database migration against existing data.

## Delivery map

| Phase | Deliverable | Depends on | Release contribution |
|---|---|---|---|
| 0 | Reproducible working baseline | Existing repository | Foundation |
| 1 | Honest evidence quality and scoring | 0 | Release A |
| 2 | Complete inventory navigation and usable setup | 0; consumes 1 | Release A |
| 3 | Reliable collection for a declared permission subset | 1 | Release A |
| 4 | Precise, accountable human reviews | 1, 2; supported evidence from 3 | Release A |
| 5 | Manual fulfillment, verification, and case evidence | 3, 4 | Release A: useful read-only assessment |
| 6 | Cross-source person/account correlation | Stable source IDs from 3; review identity rules from 4 | Release B |
| 7 | Access requests, expiry, exceptions, and recurring reviews | 5; cross-source bundles additionally require 6 | Release B: repeatable access lifecycle |
| 8 | One narrowly scoped production executor | 3, 4, 5; execution recovery and operational gates | Release C: controlled automation |
| O | Production security, recovery, operations, and scale | Starts at 0; gates production use of any release | All releases |
| 9 | Measured expansion | Pilot evidence and relevant release gates | Later releases |

Release A can be developed and demonstrated with synthetic data before production readiness. Real organizational dependence requires the relevant operational gates. Release C is optional: Release A must deliver value without write credentials.

There are no calendar promises yet. Connector semantics, identity migrations, and deployment decisions are the largest uncertainties. After phase 0 and the first scoring/search patches, estimate remaining work using observed delivery speed and a declared pilot scope. Each phase can contain multiple small reviewed changes.

## Phase 0 — Establish a trustworthy baseline

**Work**

1. Inventory the current uncommitted changes and keep unrelated work intact. Record the source revision and changes included in the candidate release; do not commit or push unless requested.
2. Reproduce the previously observed failures: the deployment test asserting dashboard wording directly in `App.tsx`, and the line-length error in the connector route. Correct the real test/implementation mismatch without weakening coverage or reintroducing obsolete UI just to satisfy a string assertion.
3. Record current web tests/build, Python suite, lint, Rego tests, deployed policy fixture checks, security gate, and disposable PostgreSQL migration/schema/isolation results. Distinguish unavailable checks and skips from passes.
4. Once services and browser access are available, verify sign-in, inventory, identity evidence, review history, and export using synthetic data. Record which running image corresponds to which source revision.

**Likely code areas:** [deployment tests](../tests/test_deployment.py), [connector route](../apps/api/src/athena/routes/connectors.py), [web tests](../apps/web/tests), existing Compose verification and policy scripts. Update a baseline note with results.

**Exit:** relevant failures resolved; required checks observed; runtime/source identity recorded; no claimed end-to-end success based only on a build. Independent source/documentation work can continue while a service check is unavailable, but the missing gate stays visible.

## Phase 1 — Make evidence uncertainty explicit

**Problem:** missing activity currently receives the maximum inactivity factor and can be labeled stale access.

**Work**

- Define distinct observed-recent, observed-stale, unknown, and invalid evidence outcomes. Preserve observation time, collection window, source capability, and reason for uncertainty.
- Treat absence of usage evidence as a data-quality concern. It must not assert inactivity or silently imply that access is safe. Decide and document how unknown factors affect any aggregate score before changing arithmetic.
- Version the risk model and new result interpretation. Do not recompute or overwrite old assessments in place.
- Show evidence quality beside findings in identity, review, and report views. Keep unsupported source semantics separate from failed collection.
- Handle missing policy evaluation distinctly from a successful evaluation when presenting findings.

**Likely areas:** [risk analytics](../apps/api/src/athena/services/risk_analytics.py), [schemas](../apps/api/src/athena/schemas.py), [web types](../apps/web/src/types.ts), [coverage component](../apps/web/src/ConnectorCoverage.tsx), risk/API/UI tests. Prefer existing structured evidence fields where appropriate; assess storage needs before promising a migration-free change.

**Exit:** tests cover missing observation, missing last-use value, known old use, known recent use, invalid/future time, and unavailable activity support. None of the missing-data cases is described as proven inactivity. Prior evidence remains readable with its original model version.

## Phase 2 — Make the first useful session easy

**Work**

- Add server-side identity search and paginated inventory/review navigation with stable ordering. Preserve filters and selected items across pages and refreshes. Label loaded counts versus totals accurately.
- Provide setup preflight for source scope, latest successful collection, capabilities, assessment readiness, and next responsible actor. Show actionable errors without credentials or raw provider payloads.
- Maintain the current optional-domain fallback so graph, AI, or protection-agent outages do not unnecessarily prevent core identity work. Treat authentication failure separately.
- Use eligible-owner selection once phase 4 provides the contract. Present current evidence and case-captured evidence as separate views.

**Likely areas:** [identity routes](../apps/api/src/athena/routes/identities.py), [repositories](../apps/api/src/athena/repositories.py), [review routes](../apps/api/src/athena/routes/reviews.py), [assessment loader](../apps/web/src/assessment.ts), [dashboard](../apps/web/src/App.tsx), [review workspace](../apps/web/src/ReviewWorkspace.tsx).

**Exit:** a synthetic inventory spanning multiple pages, including at least 201 identities, can be searched and navigated without missing records or presenting page counts as tenant totals. Reviewer/admin permissions, keyboard navigation, session expiry, empty states, and source failures have meaningful checks.

## Phase 3 — Establish connector correctness and recovery

**Work**

- Choose a small supported scope first, such as specific GitHub repository assignments and specific Azure assignments. Declare identity discovery, direct/inherited access, nesting, deny/conditions, eligibility, activity, writes, and verification separately.
- Build provider-specific fixtures for direct access, group access, overlapping paths, nesting, role changes, deleted assignments, incomplete pages, and unsupported conditions. Unsupported cases must remain unknown rather than being flattened into an inaccurate permission answer.
- Standardize snapshot metadata: tenant and provider scope, start/end observation time, completeness, warnings, normalization version, and last successful checkpoint.
- Traverse every page, including empty pages carrying continuation state. Persist progress where safe. Never infer absence or mass removal from an incomplete scan.
- Implement bounded retries with provider rate-limit handling and clear permanent/configuration errors. Use deltas only where supported and test reset/replay behavior; retain authoritative full reconciliation.
- Alert on old checkpoints, repeated failures, changed collection scope, and unexpectedly large differences. A successful HTTP call alone is not a successful complete collection.

**Likely areas:** [collector contract](../apps/api/src/athena/collectors/contracts.py), [GitHub collector](../apps/api/src/athena/collectors/github.py), [Azure collector](../apps/api/src/athena/collectors/azure.py), synchronization services, [monitoring](../apps/api/src/athena/services/monitoring.py), connector tests.

**Exit:** the declared supported fixture matrix passes. Partial collection preserves last known facts with explicit staleness. Cross-tenant scope and checkpoint reuse fail safely. Source removal is distinguished from collection failure. Verification claims are limited to the proven provider semantics.

## Phase 4 — Bind reviews to the correct person and exact target

**Work**

- Represent reviewer ownership and audit attribution with tenant, issuer, and immutable subject identifiers; keep usernames as display values. Resolve eligible reviewers instead of accepting an unchecked owner string.
- Design a forward migration/compatibility approach for existing owners. Ambiguous legacy names require explicit resolution; do not guess identity matches or rewrite immutable history.
- Let a reviewer inspect and select the exact finding/entitlement. Record evidence version, source assignment identifiers, collection time, proposed action, reason, and required approval conditions.
- Support policy-backed findings without requiring an unrelated risk/anomaly run solely to open a case, after defining the evidence contract.
- Define self-review restrictions, delegation/reassignment rules, and when independent approval is required. Verify appropriate authentication strength in the deployed identity policy.
- Prevent conflicting concurrent assignments and decisions through explicit transition guards. Preserve every accepted event.

**Likely areas:** [auth principal](../apps/api/src/athena/auth.py), [review models](../apps/api/src/athena/models.py), [review service](../apps/api/src/athena/services/remediation.py), routes/schemas, review workspace, reviewed forward migrations.

**Exit:** wrong tenant, ineligible owner, reused/renamed username, departed owner, concurrent decisions, stale target, and prohibited self-review cases have tested outcomes. One recorded review clearly identifies what was considered and who had authority.

## Phase 5 — Finish the manual correction and prove its outcome

**Work**

- Add owned manual fulfillment with a due date, instructions, and evidence references. Keep the review decision separate from fulfillment status.
- Define an explicit closure goal: one assignment removed, an account disabled, or no supported effective paths to a named permission. These are different outcomes.
- After the operator records completion, schedule read-only recollection. Record verified outcome, still-present access, failed collection, or insufficient coverage. Freshness must be sufficient for the stated goal; a pre-action snapshot cannot verify a post-action result.
- Preserve alternate access paths and reopen or continue work when the goal remains unmet. Do not automatically treat a closed ticket as verified removal.
- Produce a case-scoped evidence packet containing source facts, coverage, policy/evidence versions, reviewer rationale, fulfillment events, and verification result. Preserve tenant-wide export restrictions while making appropriately scoped case evidence useful to reviewers.
- Add reminders through an approved channel when available. Initially, a visible in-app due/overdue queue is sufficient; configure external recipients before enabling notifications.

**Likely areas:** review and execution services/models, monitoring, [evidence reporting](../apps/api/src/athena/services/evidence_report.py), [report routes](../apps/api/src/athena/routes/reports.py), review/operations UI.

**Exit / Release A:** a synthetic role-change case reaches an independently observed outcome. Tests include operator-completed-but-access-present, second access path, incomplete verification, and mismatched target. A prospective user can explain the finding and complete the supported workflow without developer intervention; record where assistance was needed.

## Phase 6 — Connect one person's accounts across providers

**Work**

- Define a separate person/workload and provider-account relationship rather than treating a source account as a universally unique person.
- Choose the authoritative identity source and supported matching attributes for the pilot. Retain source IDs, link evidence, confidence/reason, and versioned correction history.
- Provide proposed links, ambiguous/unlinked accounts, human confirmation where needed, and reversible link correction. Do not auto-merge based solely on a matching display name or email.
- Keep service principals, managed identities, shared accounts, and human identities distinguishable. Model ownership separately from account identity.
- Add cross-source inspection only after link quality is established. Do not reinterpret historic evidence silently after a link correction.

**Likely areas:** models and forward migrations, normalization services, repositories, identity UI, tenant-integrity and correlation tests. Define this model in a separately reviewed design before implementation.

**Exit:** renamed users, recycled emails, multiple accounts, ambiguous matches, unlinked accounts, workloads, and cross-tenant lookalikes are handled explicitly. Existing source-specific identifiers and history remain intact.

## Phase 7 — Add a small, complete access lifecycle

Implement in this order rather than opening several unfinished workstreams:

1. A small request catalog for already-proven resource/permission combinations, with owner, eligibility, justification, and maximum duration.
2. Recorded approval/denial, cancellation, timeout, and changed-evidence handling. Policy eligibility and human approval stay separate.
3. Manual fulfillment and read-back verification reused from phase 5. Multi-resource requests expose partial fulfillment.
4. Expiration and exceptions with explicit scope, rationale, owner, end date, reminders, and review. Automatic scheduling of a review/removal request is not automatic authorization for a new destructive action. Define the exact duration-bound human authorization contract before enabling automatic expiry execution.
5. Recurring review campaigns with fixed evidence scope, reviewer assignment, reassignment, overdue handling, and recorded results.

**Likely areas:** new narrowly scoped request/campaign modules, models/migrations, OPA policy contracts and fixtures where policy changes are needed, existing review/fulfillment/monitoring components, request/review UI.

**Exit / Release B:** one request completes its supported lifecycle; denied/expired approval cannot create access; expiry does not falsely claim removal; campaigns retain their original evidence references. Cross-source bundles require phase 6 and each source's conformance gate.

## Phase 8 — Introduce one controlled executor

**Work**

- Select one operation with proven semantics and pilot demand. Do not begin with broad group deletion or generalized “remove all access.”
- Use a separate runtime identity and narrow write credentials. Do not broaden collector tokens.
- Bind execution authorization to tenant, immutable principal, source scope, resource, entitlement, source assignment ID, evidence/policy version, permitted operation, and approval expiry. Revalidate immediately before acting.
- Add execution leases, heartbeats, bounded attempts, cancellation, and recorded recovery. A worker can die after a successful provider operation; recovered work must reconcile before repeating a write.
- Define idempotent outcomes for already absent/present assignments and source-specific failures. Credential/configuration errors require operator action rather than endless retries.
- Verify the exact closure goal using new source evidence. Evaluate whether separate read credentials/verifier improve independence. A response from the same adapter is not assumed independent proof.
- Add operation limits, anomaly thresholds, a stop switch, and a manual fallback. Any compensating access grant is a new authorized action, not an automatic rollback assumption.

**Likely areas:** [execution service/worker](../apps/api/src/athena/services/execution.py), a single provider adapter, models/migrations for leases and authorization binding, monitoring/operations UI, execution and tenant tests.

**Exit / Release C:** a test tenant proves exact targeting, approval expiry, changed-target rejection, ambiguous response recovery, crash-after-success, duplicate delivery, alternate paths, and stop-switch behavior. Production activation follows reviewed adapter scope and operational readiness. An approval recorded by this plan is not an execution authorization.

## Track O — Production readiness starts at phase 0

Follow the existing [deployment/recovery plan](production-deployment-plan.md); the [readiness manifest](../governance/readiness.json) remains the authority. This plan does not duplicate or silently change that contract.

| Workstream | Start | Required result |
|---|---|---|
| Scope and ownership | Phase 0 | Named product/security/operations owners; pilot data classification, hosting choice, approved region/residency, cost ceiling, support expectations |
| Identity and network | Before real-data pilot deployment | Verified OIDC claims/roles, reviewer/admin authentication policy, TLS, controlled ingress/egress, private data services as required |
| Secrets and tenant isolation | Before real-data deployment | Separate runtime/migration/executor identities; rotation and break-glass exercise; real PostgreSQL isolation checks and scoped logs/exports |
| Resource protection | During phases 1–3 | Per-user/tenant budgets and concurrency limits for expensive explanations, reports, graph queries, and jobs; abuse/load tests |
| Observability | During phases 2–5 | Separate process, database, policy, connector freshness, workflow and verification health; alert delivery to named owners |
| Recovery | Before production dependence | Backup/restore rehearsal, evidence integrity checks, measured recovery against approved objectives, documented incident process |
| Release integrity | Every deployable release | Tested source linked to image digest, retained test/SBOM/scan evidence, staged rollout and rollback verification |
| Capacity and usability | Before declaring supported scale | Declared tenant size and workload; measured latency, collection/verification lag, job recovery, and authenticated task completion |

The existing recovery plan specifies a 15-minute RPO, 120-minute RTO, and 30-day restore-test interval. Treat these as repository targets to confirm with the deployment owner and then measure; they are not achieved results. Hosting and cost decisions are required before provisioning infrastructure, but do not block the first local product patches.

## Phase 9 — Expand only after measuring the core workflow

Choose work from pilot evidence: additional connectors, machine-identity ownership and workload trust, more complete permission semantics, change preview, ticketing integration, richer exports, or evidence-grounded AI assistance. Each addition must improve an identified task and carry explicit source/verification limits.

For AI, retain advisory-only behavior, tenant-scoped retrieval, bounded evidence, claim-level references, and abstention when facts are insufficient. For graph expansion, retain normalization versions and prove provider semantics. Do not use a higher connector count or more dashboards as a substitute for completion rate and evidence accuracy.

## First patches: exact starting order

| Patch | Concrete scope | Validation before moving on |
|---|---|---|
| P00 — Baseline repair | Reproduce and resolve current lint and dashboard-test mismatch; record source/runtime state | Relevant test/lint checks pass; unavailable infrastructure checks explicitly remain open |
| P01 — Evidence quality contract | Specify recent/stale/unknown/invalid activity, scoring treatment, and backward-compatible result versioning | Worked examples reviewed against current missing-data behavior; no unsupported safety inference |
| P02 — Unknown activity correction | Implement that contract in risk output, API interpretation, and displayed finding reasons | Missing observations never generate a proven-stale explanation; old assessments remain intact |
| P03 — Inventory navigation | Server search and multi-page inventory navigation; accurate counts and selection | More-than-one-page fixture and keyboard/session/error cases pass |
| P04 — Connector conformance baseline | Publish supported GitHub/Azure subset and fixtures for completeness, overlap, and unsupported semantics | Partial snapshots cannot be mistaken for removals; supported permission cases match expected source results |
| P05 — Review target and owner design | Define immutable reviewer binding, legacy-owner transition, exact finding target, and permitted state transitions | Ambiguities and migration impact explicit; no silent reassignment of old evidence |
| P06 — Review implementation | Add owner/target contracts and conflict guards to service/API/UI | Role/tenant/owner/concurrency tests and signed-in synthetic workflow pass |
| P07 — Manual fulfillment and verification | Add fulfillment ownership, closure goals, read-back outcomes, and case evidence | Demonstrate one correction and one deliberately incomplete correction without false closure |

P00 starts the work. P01/P02 address the first substantive product defect. Implement P03 and collection improvements without bundling unrelated changes into the scoring patch. P05/P06 require the applicable auth/model/migration review; prepare the concrete design and migration evidence before requesting any live operation.

## Acceptance and measurement

Each completed code slice has relevant behavioral tests and the repository-required verification, including real PostgreSQL/Rego/security-gate checks when required and available. Policy changes include exact allow/deny fixtures. Database changes require forward migration, drift, tenant-isolation, and immutability checks against disposable PostgreSQL. A mocked UI or SQLite-only result cannot prove deployed PostgreSQL/security behavior.

Track these measures from the first synthetic workflow, then the pilot:

- time to first useful finding and points where a user needs help;
- proportion of findings with current, supported evidence;
- unknown versus observed-stale findings and disputed finding reasons;
- inventory search/task completion across page boundaries;
- review age, overdue work, and decision-to-observed-outcome time;
- collection lag, incomplete runs, retries, and recovery time;
- verified outcomes separately from approvals, ticket completions, and provider responses;
- operating cost and p50/p95 latency at a stated tenant/workload size.

Set numerical service objectives with the pilot owner after measurement. Correctness requirements such as zero cross-tenant disclosure and no false verified closure are release gates, not statistical targets to average away.

## Decisions to resolve at the appropriate phase

No further product decision is needed to begin P00–P03. Later decision points are:

| Decision | Needed by | Working default until resolved |
|---|---|---|
| First pilot team and exact resource subset | Phase 3 | Synthetic GitHub/Azure examples; no universal coverage claim |
| Authoritative person source and identity-match rules | Phase 6 | Preserve source-specific accounts and unresolved links |
| Which review types require independent approval | Phase 4 | Design explicit rules; do not assume self-assignment establishes independence |
| First request type and allowed duration/expiry behavior | Phase 7 | Small single-source catalog with manual fulfillment |
| First automated operation and execution authorization | Phase 8 | Manual fulfillment with read-only verification |
| Hosting, ownership, cost, residency, recovery targets | Track O before infrastructure/real-data dependence | Local synthetic development; existing production status remains blocked |

Suggested responsibilities are functions, not assumed staff: product owner defines the user promise; backend owns contracts and jobs; frontend owns task completion; security owns authorization and negative cases; operations owns deployment and recovery. One person may cover several functions, but required independent approval must still be preserved.

## Planning validation

This document organizes existing code findings and cited research into proposed work. Only this plan is created by this task. No application changes, new dependencies, tests against live services, migrations, deployments, commits, or upstream access changes were performed. Prior failing/unavailable checks remain baseline items until freshly resolved and verified.
