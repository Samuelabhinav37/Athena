# Athena: advantages, attack surfaces, workflow gaps, and a practical improvement plan

Research date: 7 September 2026. Code basis: `7bd2234` plus the current uncommitted working tree. Companion: [interactive strategy page](athena-strategy.html), [competitor research](athena-competitor-research-2026-09-07.md), and [system walkthrough](athena-walkthrough.html).

## Assessment

Athena has a credible foundation for **read-only access assurance**: collect permissions, explain their origin, identify governance problems, route a human review, and preserve evidence. Its strongest design choice is separating authoritative policy from advisory analytics and AI, and separating approval from verified execution.

Its largest weakness is the distance between those components and a dependable user outcome. Incomplete source semantics, ambiguous missing-data treatment, manual setup, bounded inventories without page navigation, and unfinished fulfillment/recovery behavior can undermine confidence even when individual services work. Production readiness is explicitly blocked in the [readiness manifest](../governance/readiness.json).

The recommended initial promise is: **“Connect one source, find a defensible access issue, assign the correct owner, and prove what happened next.”** Start with GitHub and Entra/Azure only where the supported permission semantics are clear. This is a positioning hypothesis for a small security/IT team, not validated market demand or a claim of uniqueness.

## Evidence and limits

- **Observed** means directly visible in inspected source, contracts, or existing local check results.
- **Inferred risk** describes what could happen under stated conditions. It is not a reproduced vulnerability.
- **Proposed** means future work, not a current protection or feature.

This was a defensive architecture and product assessment using local source and official external documentation. No live attack, provider access change, dependency installation, database migration, or penetration test was performed. Vendor documentation establishes documented functionality, not independent proof of security, operating quality, or configuration in a particular customer tenant. No CVSS scores, breach probabilities, vendor rankings, or pricing comparisons are asserted.

## Advantages and their tradeoffs

| Advantage observed in Athena | Why it helps | Cost or limitation |
|---|---|---|
| Read-only collector contracts and approved provider scope bindings | Useful investigations can begin without granting Athena permission to change upstream access | Read-only access still exposes sensitive identity and permission information; remediation requires a separate process |
| Versioned provenance and policy inputs | A reviewer can inspect why an entitlement exists and which rules evaluated it | Reproducibility does not make incomplete source facts correct; historical coverage starts when observations exist |
| OPA authority; advisory ML/AI; recorded human review | A misleading model answer cannot directly issue an access change through the intended architecture | A human can still be persuaded by misleading explanations; approval can also become a bottleneck |
| Tenant-scoped constraints, forced PostgreSQL RLS, and append-only evidence | Multiple layers reduce accidental cross-tenant access and preserve accountability | These controls depend on correct roles and runtime context; they are not a boundary against a fully compromised host or database administrator |
| Portable JSON/Markdown reports and a rebuildable Neo4j projection | Evidence remains usable without a particular graph engine or AI provider | A digest is not a signature, trusted timestamp, backup, or proof that source facts are true |
| Monitoring leases, recorded steps, and completed-schedule idempotency | Ordinary job retries and overlapping schedule attempts have explicit behavior | Execution workers have a different recovery model and need their own hardening; monitoring success does not prove provider freshness |

Code: [collector contract](../apps/api/src/athena/collectors/contracts.py), [scope binding](../apps/api/src/athena/services/connector_scopes.py), [provenance](../apps/api/src/athena/services/provenance.py), [policy evaluation](../apps/api/src/athena/services/policy_evaluation.py), [explanations](../apps/api/src/athena/services/explanations.py), [tenant RLS](../apps/api/src/athena/services/tenant_rls.py), [report facts](../apps/api/src/athena/services/evidence_report.py), [monitoring](../apps/api/src/athena/services/monitoring.py).

## Concrete gaps in the current working tree

### 1. Unknown activity can look like stale access — observed, fix first

`RiskAnalyticsService._factors` sets `time_factor = 1.0` when an observation or `last_used_at` is missing. The weight for this factor is 15 points. `_finding_type` can then label the finding `STALE_ACCESS` if retained-access or policy findings do not take precedence. The current collector manifests declare activity signals unsupported. This combination can create misleading findings without any attacker being involved.

Represent `known_recent`, `known_stale`, and `unknown` separately. Unknown evidence may deserve investigation, but should not be described as proven inactivity. Show the observation period and source beside the recommendation. Test absent logs, incomplete logs, old observations, and actual recent use separately. [Risk code](../apps/api/src/athena/services/risk_analytics.py), [GitHub manifest](../apps/api/src/athena/collectors/github.py), [Azure manifest](../apps/api/src/athena/collectors/azure.py), [Keycloak manifest](../apps/api/src/athena/collectors/keycloak.py).

### 2. Permission coverage remains partial — observed

Azure does not collect deny assignments or PIM eligibility, recursively expand nested groups, or fully expand inherited effective access. GitHub does not resolve parent-team relationships or establish complete grant lineage. Keycloak preserves group paths without a nested relationship graph; its current snapshot excludes service-account users despite broader README wording.

The new coverage UI already exposes connector limitations and observation timestamps. Keep it, then attach coverage to each finding and permission path. Publish provider-native fixtures for supported direct, nested, inherited, conditional, and deny cases. Unsupported cases must produce an explicit unknown result instead of a complete-access claim. [Coverage component](../apps/web/src/ConnectorCoverage.tsx), collector manifests above.

### 3. Larger inventories are difficult to navigate — observed

`loadAssessment` fetches `/v1/identities` and `/v1/reviews` without pagination parameters. These endpoints default to 100 records, and the inspected UI has no next-page traversal for these lists. Search works on loaded identities. The UI correctly labels several counts as loaded-page counts, and can fetch an identity by ID from a case, but this does not make the whole inventory searchable.

Add server-side search/filtering, pagination controls, stable ordering, and explicit loaded/total counts where a total is available. Prove the workflow with more than one page; increasing a page-size ceiling is not the solution. [Assessment loader](../apps/web/src/assessment.ts), [identity route](../apps/api/src/athena/routes/identities.py), [review route](../apps/api/src/athena/routes/reviews.py), [dashboard](../apps/web/src/App.tsx).

### 4. Review identity and separation need strengthening — observed code; abuse is conditional

`Principal.actor` returns a username. `ReviewCase.owner` is a string, and decisions compare that string with the actor. Assignment accepts an owner string; the inspected service does not resolve an eligible immutable principal or require an independent assigner. An authorized reviewer can assign themselves. Whether this violates intended policy depends on the review type; it is not by itself proof of an authorization bypass.

Use tenant + issuer + immutable subject IDs for ownership and audit attribution, retaining names only for display. Resolve eligible reviewers, handle departures, and define when self-review or single-person control must be prohibited. Add concurrency guards to assignment/decision transitions. Ordinary reviewer MFA strength is not checked here like break-glass authentication is; enforce and verify an appropriate IdP authentication policy. [Auth](../apps/api/src/athena/auth.py), [review service](../apps/api/src/athena/services/remediation.py), [models](../apps/api/src/athena/models.py).

### 5. Review-to-fulfillment is not a complete access lifecycle — observed

Opening a review currently requires risk or anomaly evidence; a policy finding alone is insufficient. The service normally selects the highest-scored risk entitlement and reuses an active identity-level case. This can make a reviewer’s intended target less obvious. The UI exposes retain/revoke/extend/exception decisions, but an extend decision does not implement time-bound fulfillment and exception recording does not establish a recurring expiration workflow.

Make the selected entitlement, current source state, exact finding, owner, and next action explicit before recording a decision. Complete manual fulfillment plus read-only verification first. Add request catalogs, reminders, delegation, expiration, and recurring campaigns only as complete user workflows. [Review service](../apps/api/src/athena/services/remediation.py), [review workspace](../apps/web/src/ReviewWorkspace.tsx), [execution contract](remediation-execution.md).

### 6. The execution framework needs failure and stale-approval defenses — observed omissions; no exploit demonstrated

The request records a target snapshot. `ExecutionService.run` reconstructs the target from current records but has no explicit equality check against that approved snapshot, approval-age limit, or renewed review check immediately before invoking the injected adapter. A crash after committing `RUNNING` can leave work outside `ExecutionWorker.run_next` selection, which only chooses pending/failed/verification-failed records. Unlike monitoring, this execution path has no visible lease expiry or stale-running recovery.

Before enabling production adapters, bind authorization to the exact target and evidence version, impose approval expiry, and revalidate preconditions. Add lease recovery and reconciliation after an ambiguous provider response. A retry must first establish whether the earlier operation succeeded; do not blindly repeat a destructive action. Verify effective access as well as the targeted grant where provider semantics permit, because another path may retain access. [Execution service and worker](../apps/api/src/athena/services/execution.py), [monitoring comparison](../apps/api/src/athena/services/monitoring.py).

### 7. Expensive work has uneven protection — observed route gap; impact unmeasured

Telemetry routes contain explicit rate-limiter dependencies. The inspected viewer-accessible explanation route and administrator report routes do not have equivalent endpoint-specific quota dependencies; `main.py` installs observability middleware, not a global admission controller. Explanation size and provider timeout limits exist, which is useful, but do not bound repeated concurrent requests. A production ingress could add controls; its deployed configuration was not verified.

Add per-tenant/user quotas, concurrency budgets, caching by evidence digest where appropriate, bounded report jobs, and provider spending limits. Test load isolation between synthetic tenants. [Identity explanation route](../apps/api/src/athena/routes/identities.py), [report routes](../apps/api/src/athena/routes/reports.py), [telemetry routes](../apps/api/src/athena/routes/telemetry.py), [OWASP resource-consumption guidance](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).

### 8. Operations remain a release blocker — observed manifest

The repository has security tests, dependency locking, Python auditing, SBOM generation, image scans, and an operations plan. These are advantages. The manifest still lacks approved deployment, recovery, production identity administration, centralized alerting, and scale evidence. `/ready` checks PostgreSQL connectivity only; it is not an end-to-end assessment of OPA, source collection, or analyst success. Documentation and a passing build do not replace a restore rehearsal or an exercised incident response.

Keep process liveness, database readiness, policy capability, connector freshness, and user-journey health separate. The UI’s existing optional-domain fallback is an improvement over older research: protection-agent failures no longer necessarily block core evidence, and expired sessions are not disguised as an optional outage. [Readiness](../governance/readiness.json), [API health endpoints](../apps/api/src/athena/main.py), [supply chain](../.github/workflows/supply-chain.yml), [assessment loader](../apps/web/src/assessment.ts).

## How attackers could target Athena

These are defensive scenarios, not instructions for attacking a deployment. Priority reflects proposed engineering order, not a measured likelihood or CVSS rating.

| Scenario and prerequisite | What the attacker could seek | Existing defense | Remaining work / safe validation |
|---|---|---|---|
| Compromised reviewer/admin session | Read the entitlement map, steer reviews, or request harmful remediation within that role’s authority | Signature/issuer/audience/age validation, tenant membership, role checks, recorded owner decisions; web CSP | Verify phishing-resistant admin/reviewer authentication and session handling; immutable owner IDs; independent approval where required; synthetic role-matrix tests |
| Cross-tenant object access through a future authorization mistake | Read another tenant’s identities, reviews, exports, or graph results | Tenant-scoped queries, composite constraints, forced RLS and runtime role separation | Negative tests for every new object route, background job, export, and graph projection; validate actual runtime role privileges. No bypass was found or reproduced here |
| Manipulated provider facts or missing collection coverage | Hide meaningful access, influence peer baselines, or flood the queue with doubtful findings | Read-only snapshots, source identifiers, explicit manifests, advisory scores | Treat source data as observations; expose unknowns; reconcile complete snapshots; detect unexpected scope/volume changes; validate against provider truth |
| Indirect prompt injection in provider-controlled text | Produce a misleading explanation that persuades a human reviewer | Bounded evidence, structured output, no tools, advisory-only path, external evidence minimization | Per-claim evidence links, abstention, adversarial fixtures and reviewer UX tests. JSON schema validity does not establish factual correctness |
| Repeated expensive requests using a valid low-privilege account | Exhaust API/AI capacity or incur cost | List bounds, explanation size/time limits, some route-specific limiters | Apply explanation/report admission limits and tenant budgets; measure load in an isolated environment |
| Source state changes after approval, or compromised future executor | Execute a decision against stale context or provide misleading completion evidence | Separate adapter contract, pending state, idempotency, verification method, event history | Exact approved-target binding; expiry; separate read-back trust where practical; reconcile alternate access paths and crash-after-success cases |
| Stolen webhook/agent credentials or replay attempts | Inject apparently legitimate telemetry or consume storage/processing capacity | Timestamp/signature verification, delivery identity, replay reservations and configured shared controls | Rotate keys, constrain source/tenant scope, alert on rejection patterns; test simultaneous replay across replicas. A valid signature identifies a key holder, not the truth of an event |
| CI/host/database administrator compromise or ransomware | Replace application behavior, steal connector secrets, or destroy/replace evidence | Locked dependencies, image scans, append-only application/runtime controls | Digest-bound promotion, provenance/signature design, isolated backups, least-privilege CI, rotation, and exercised recovery. A checksum stored beside a replaced file can also be replaced |

Technical references: [OWASP object authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP prompt injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [NIST authentication guidance](https://pages.nist.gov/800-63-4/sp800-63b.html), and [PostgreSQL RLS privilege boundaries](https://www.postgresql.org/docs/current/ddl-rowsecurity.html). RLS protects normal scoped access; PostgreSQL documents bypass privileges. Athena’s trusted application sets its transaction tenant context, so a fully compromised application/database credential must not be assumed confined by that context alone.

## Why the experience is not yet smooth

| User moment | Current friction | Better experience and acceptance evidence |
|---|---|---|
| Connect the first source | Deployment configuration, scope approval, synchronization, and assessment are separate administrator tasks | Guided preflight with safe error messages, a synthetic sample tenant, clear owner for each step; new user completes setup without developer assistance |
| Find the relevant account | Source-specific records and first-page local search | Server-side search, pagination, explicit source scope; proposed cross-provider linking must require stable evidence and human correction, not email-only auto-merges |
| Decide if a finding is real | Missing usage can look stale; source semantics differ | Known/unknown evidence states, observation dates, unsupported-path warnings, and actionable reason codes |
| Assign a review | Free-text owner username, indirect target selection | Eligible-owner picker using stable IDs; exact entitlement and source facts beside the action |
| Finish a review | Resolved case can coexist with pending execution; report export requires administrator | Persistent outcome timeline, fulfillment owner, reminders, and verified read-back. Offer appropriately scoped reviewer evidence instead of granting broad tenant export solely for convenience |
| Recover from trouble | Multiple services and manual configuration; old demo images can differ from code | Release diagnostics, dependency-specific health, safe retries, tested recovery instructions, and one signed-in smoke journey |

The existing `ReviewWorkspace` and `ConnectorCoverage` already improve clarity. Build on them rather than claiming those capabilities are absent. The signed-in workflow has not been visually verified in this session. [Dashboard](../apps/web/src/App.tsx), [review UI](../apps/web/src/ReviewWorkspace.tsx), [earlier audit](audit-2026-09-06.md).

## What comparable companies teach us

The [companion vendor research](athena-competitor-research-2026-09-07.md) supplies current official citations and boundaries. Microsoft Entra, SailPoint, ConductorOne/C1, and Veza solve overlapping but different parts of identity governance. Their published workflows illustrate that discover → approve → fulfill → reconcile → review is a maintained lifecycle, not a single risk dashboard. No public documentation reviewed here establishes that any vendor prevents every attack or removes the customer’s responsibility for configuration and ownership.

| Company | Documented mechanism | Lesson for Athena |
|---|---|---|
| Microsoft Entra | Access packages, recurring reviews, lifecycle workflows and PIM; provisioning logs distinguish actionable failures. [Governance](https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview), [logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-analyze-provisioning-logs) | Give access a beginning, owner, expiry, and observable outcome |
| SailPoint | Certification remediation can become a direct change or a manual source-owner task. [Certifications](https://documentation.sailpoint.com/saas/help/certs/understanding_certifications.html) | Manual fulfillment is a legitimate workflow that needs accountability |
| C1 / ConductorOne | Separate approval policies, temporary access, connector health checks, bounded retries and fallback. [Policies](https://www.c1.ai/docs/product/admin/policies), [health](https://www.c1.ai/docs/baton/health-checks) | Make failure recovery and escalation part of the product |
| Veza | Effective-permission graph and per-attempt remediation reporting. [Product](https://veza.com/product/), [release details](https://veza.com/blog/veza-product-updates-may-2026/) | Connect permission origin to recorded remediation outcomes |

For Athena, adopt the patterns rather than their whole feature catalogs: resource-specific connector contracts; clear manual versus automated fulfillment; recurrent access review; visible sync failures; least-privilege administration; and permission answers with freshness and limitations. Athena’s opportunity is a small, defensible evidence workflow with transparent boundaries. It should not claim to replace a mature enterprise governance platform today.

## Ordered improvement plan

These are proposed milestones, not committed dates or authorization to change production access.

| Order | Deliverable | Exit gate | Suggested owner |
|---|---|---|---|
| 1 — Trust the answer | Repair unknown/stale scoring, page navigation, explicit review target, current test/lint findings, documentation drift | Absent activity never claims proven inactivity; a multi-page inventory is searchable; reviewer sees exact evidence and target; relevant checks pass | Backend + frontend |
| 2 — Close one review | Stable owner identity, eligibility and required approval separation, manual fulfillment owner, reminders, read-only outcome verification | A synthetic case progresses from finding to recorded decision to independently observed outcome; changed/stale evidence reopens review where required | Identity/security + product |
| 3 — Prove resilience | Complete supported connector semantics, quota controls, retry/cursor handling, execution leases/preconditions before adapters | Throttling, expired cursor, duplicate event, source outage, wrong tenant, concurrent decision, and worker-crash cases have defined tested outcomes | Backend + security |
| 4 — Earn production readiness | Approved hosting/ownership, secret rotation, deployment identity checks, observability, backup restore, release promotion, supported-size benchmarks | Evidence closes every blocker in the readiness manifest; measured recovery meets approved objectives; signed-in acceptance is repeatable | Operations + security |

For collection maintenance, GitHub documents honoring `Retry-After` and rate-limit responses. Microsoft Graph delta supports change tracking for specific resources, with replay, delay, and reset behavior to handle; it is not a universal Azure RBAC change stream. Use provider events/deltas for prompt updates plus periodic authoritative reconciliation. [GitHub API practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api), [Graph delta semantics](https://learn.microsoft.com/en-us/graph/delta-query-overview).

For telemetry, an OpenTelemetry Collector can provide queues and retries, but queue saturation, retry expiry, and storage failures remain possible. It does not make Athena’s normalization-only endpoint durable. Add explicit acceptance/storage semantics before claiming durable ingestion. [Collector resilience](https://opentelemetry.io/docs/collector/resiliency/), [Athena telemetry boundary](telemetry.md).

## Operating and maintaining the system

Proposed cadence, to be adjusted with the operating team:

- **Continuously:** monitor collection lag and completeness, OPA errors, review backlog, execution age, queue saturation, API/AI budgets, and tenant-boundary rejections. Route each alert to a named owner.
- **Each release:** run unit and integration checks, real PostgreSQL isolation/migration tests in a disposable environment, deployed OPA fixture checks, dependency/SBOM/image checks, and a signed-in user journey. Compare running image digests to the tested release. Do not equate source-test success with deployment success.
- **Weekly:** review disputed findings, abandoned setup attempts, API deprecations, permission-scope changes, and aging manual fulfillment. Use these results to choose work rather than increasing connector count blindly.
- **On an approved recovery schedule:** rehearse restoration and credential rotation, verify retained evidence, and measure actual recovery objectives. Athena’s current plan proposes monthly restore exercises; that proposal is not evidence an exercise has occurred.

Measure time to first useful finding, unsupported-finding rate, collection lag, reviewer completion time, overdue cases, and decision-to-verified-outcome latency. Report p50/p95 timings at a stated tenant size and distinguish approved, executed, and verified counts. Select service objectives with pilot users; no adoption, scale, or cost benchmark has been measured by this research.

## Validation status

The earlier 7 September checks in this conversation observed: web tests **5 passed**; TypeScript/Vite build passed; Python **282 passed, 1 failed, 8 skipped**; one E501 in `routes/connectors.py:25`. The Python failure is `test_dashboard_exposes_analyst_command_center_and_safe_setup_status`, which expects wording directly in `App.tsx`. These are baseline findings, not results of fixing them in this research.

Docker was unavailable and no browser was connected in that earlier inspection. PostgreSQL migrations/RLS runtime checks, deployed Rego/security-gate execution, visual layout, and authenticated end-to-end behavior were therefore not freshly established. This documentation task does not resolve those application or deployment findings. The HTML artifact receives separate syntax, link, and interaction checks; those cannot establish Athena’s runtime security.

Artifact validation in this research turn passed: balanced HTML tags, 52 unique IDs, label/control references, static and dynamic local links, both Markdown files’ local links, JavaScript syntax, four tab panels with keyboard navigation, five system stages, eight threat scenarios, four vendor selections, four improvement phases, and the timing model at default/minimum/maximum values. Interactions were evaluated with a lightweight local DOM harness. Browser discovery again returned no connected browsers, so rendered layout remains unverified. `git diff --check` passed, with an existing Git line-ending notice for `apps/web/src/types.ts`. No application test suite was rerun for these documentation-only additions.
