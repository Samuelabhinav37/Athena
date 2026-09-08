# Making Athena useful: gaps, differentiation, and delivery roadmap

Research date: 2026-09-06. Repository basis: `7bd2234` plus the uncommitted audit fixes
recorded in [the audit follow-up](audit-2026-09-06.md). This research changes documentation
only. It does not approve infrastructure spending, dependency additions, or connector writes.

## Recommendation

Athena's strongest initial product is a read-only authorization-assurance tool for a small
security or IT team using GitHub and Microsoft Entra/Azure: find consequential access,
explain its origin, route a review, and preserve verifiable evidence of the outcome.
That audience is a working hypothesis, not validated demand. Large-enterprise replacement
and a personal identity lab would require different priorities.

The main shortfall is the distance between technical capabilities and completed user tasks.
Passing 289 Python tests, policy checks, and a security gate establishes a valuable engineering
baseline. It does not establish onboarding success, permission accuracy across providers,
reviewer usefulness, operating cost, customer trust, or production readiness.

Build this first user promise:

> Connect a source with read-only access, identify a meaningful access issue, show the
> supporting facts and limitations, assign an owner, and export a defensible review record.

Keep the existing deterministic-policy, advisory-AI, human-approval separation. A useful first
release can record manual remediation and independently observe its outcome without possessing
upstream write credentials.

## Evidence and research limits

This combines current source inspection, repository capability contracts, the preceding local
audit, and official provider/product documentation. Vendor documentation demonstrates documented
behavior, not independently benchmarked accuracy or adoption. No customer interviews, pricing
study, usability trial, penetration test, or live-provider conformance exercise was performed.

The [companion workflow research](adoption-workflow-research.md) covers Entra, ConductorOne,
and Veza. The older [enterprise comparison](enterprise-competitive-research.md) supplies broader
context; this report focuses on actionable gaps and does not revalidate every older vendor claim.

## What Athena already has

- Identity and entitlement collection, source-linked provenance, deterministic OPA policy,
  advisory risk/anomaly analysis, review cases, and an execution framework.
- Tenant isolation and append-only evidence controls, with fresh disposable PostgreSQL checks
  passing in the preceding audit.
- A React analyst dashboard, machine-identity posture, bounded graph queries, and portable
  digest-verified JSON/Markdown reports.
- Generic telemetry normalization/export contracts and a separate persisted browser/mailbox
  security-event domain. These two ingestion boundaries must not be conflated.

Sources: [README](../README.md), [audit](audit-2026-09-06.md),
[remediation](remediation-execution.md), [telemetry](telemetry.md),
[security agents](security-agents.md), [reports](portable-reports.md).

## Gaps that matter to a user

| Priority | Gap and evidence | Consequence | Proposed improvement |
|---|---|---|---|
| P0 | Signed-in analyst journey remains unverified; demo rollout needed local configuration repair ([audit](audit-2026-09-06.md)) | A new user may never reach useful evidence | Guided setup, safe configuration preflight, a sample tenant, release/version diagnostics, and task-based browser tests |
| P0 | Connector contracts declare partial inheritance and unsupported deny/eligibility/activity semantics ([matrix](connector-sdk.md)) | A permission answer can be incomplete even when collection succeeds | Visible per-object coverage and freshness; explicit unknown states; provider-native expected-result fixtures |
| P0 | Reviews exist, but production GitHub/Azure write adapters do not ([execution contract](remediation-execution.md)) | Approval does not prove a correction occurred | Complete owner-to-review-to-verification flow; start with manual fulfillment and subsequent read-only reconciliation |
| P1 | Sources identify records by tenant/source/external ID; inspected model has no explicit cross-provider person-link entity ([models](../apps/api/src/athena/models.py)) | One person can appear as unrelated accounts | Reviewed identity links using stable evidence, ambiguity handling, split/unlink history; never silently merge by display name or email alone |
| P1 | Azure full snapshots, limited cursors, unsupported retry capabilities, and offset pagination remain ([capacity](performance.md), [matrix](connector-sdk.md)) | Throttling, long syncs, and incomplete answers as tenants grow | Checkpoints, bounded provider-aware retries, supported delta feeds, periodic reconciliation, visible failed/partial runs, cursor navigation |
| P1 | Generic telemetry acknowledges normalization rather than durable acceptance ([telemetry](telemetry.md)) | An HTTP success can be mistaken for a retained security record | Define durable acknowledgement, tenant quotas, replay semantics, backpressure, retention, and delivery monitoring before marketing ingestion |
| P1 | Machine posture reports missing owners/usage but activity coverage is limited ([machine identities](machine-identities.md)) | Teams cannot reliably distinguish unused from unobserved accounts | Owner workflows, evidence coverage windows, repository/application context, expiring exceptions, verified decommissioning |
| P1 | Production manifest remains blocked ([readiness](../governance/readiness.json)) | Users cannot responsibly depend on the system for ongoing operations | Supported deployment, restore rehearsal, secrets/TLS/OIDC operations, alert delivery, upgrade/rollback evidence, measured capacity |
| P2 | JSON/Markdown are implemented; PDF/Word and OSCAL Assessment Results remain blocked ([formats](portable-reports.md)) | Evidence needs manual packaging for some stakeholders | A readable review packet first, then schema-validated assessment exports and rendered document formats based on actual demand |

Cross-provider identity linkage is an inspection finding, not proof that no correlation logic exists
anywhere. Validate that seam before designing a new model. Similarly, usability and accessibility
are unverified, not established failures.

## Accuracy must precede more connector logos

Azure can deny an action despite a role assignment, and role assignments can carry conditions.
The existence of an assignment is therefore insufficient to claim unrestricted effective access.
[Azure deny assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments),
[role assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments).

Future AWS coverage would need explicit-deny precedence, identity/resource policies, permission
boundaries, and organization controls; a generic group-membership graph cannot stand in for that
evaluation. This is a reason to defer AWS until its semantics can be tested, not an assertion that
Athena currently supports AWS. [AWS policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

For every result, separate:

1. Provider-observed assignments and source timestamps.
2. Derived access paths, assumptions, and unsupported conditions.
3. Athena's deterministic governance-policy assessment.
4. Actual observed use, if available, with its observation window.

OPA deciding an Athena governance rule does not prove that Azure or GitHub would authorize an
arbitrary live request. Unknown activity must not be labeled unused access. Missing collection
must not become a deletion or a clean bill of health.

Acceptance fixtures should cover direct and inherited grants, nested groups, denies, conditional
access, eligible versus active privileges, expired grants, deleted/recreated accounts, partial pages,
rate limits, cursor invalidation, and a lost permission to read one provider endpoint. Mark unsupported
fixtures explicitly rather than fabricating a complete answer.

GitHub recommends webhook use where possible and respecting provider retry/rate-limit signals.
Microsoft Graph delta queries track supported resource changes without rereading the entire
collection; support is resource-specific and does not automatically extend to Azure ARM RBAC.
Use events for prompt refresh plus periodic authoritative reconciliation, not events alone.
[GitHub API practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api),
[Graph delta query](https://learn.microsoft.com/en-us/graph/delta-query-overview).

## Features that could make Athena particularly valuable

These are proposed differentiation, not claims of market uniqueness.

**Access history with an explanation.** Ask, “Why did this account gain production access on
Tuesday?” Show the relevant source change, lineage, review, policy version, and observation times.
Define whether a date means provider-effective time or Athena-observed time. Historical answers
must not claim completeness where collection was absent.

**A review queue that leads to closure.** Prioritize consequential, well-supported findings;
show owner, business context, confidence limitations, due date, and recommended next step.
Add saved filters, delegation, reminders, expiring exceptions, and ticket handoff. Keep approved,
executed, and independently verified states distinct. Entra's access-package model demonstrates
that requests, approvals, expiration, and reviews are established workflow expectations.
[Entitlement management](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview).

**Evidence-backed questions.** Natural-language questions can select bounded, tenant-scoped read
operations and explain returned facts with clickable evidence references. Require abstention when
evidence is missing and evaluate unsupported claims and prompt injection. Start with useful
questions such as “Which privileged service accounts have no owner?” and “What changed since the
last review?” Do not grant the model arbitrary SQL, Cypher, policy-writing, or execution authority.

**Machine identities connected to development workflows.** Extend ownership beyond a name to the
application, repository, environment, and cloud trust relationship. A promising later slice is
GitHub Actions-to-Azure workload trust: which workflow can obtain which cloud privileges, under
which claim conditions, and who owns the relationship? GitHub documents short-lived OIDC token
exchange and claim matching, so credential age alone is insufficient for this class of identity.
This requires new collection semantics and is not an existing Athena capability.
[GitHub Actions OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).

**A portable evidence packet.** Bundle facts, collection completeness, reviewer rationale,
policy version, and observed remediation outcome. Preserve offline verification. A digest proves
internal consistency against an expected digest; by itself it does not establish author identity,
trusted timestamp, or the truth of collected facts. Add signatures/trusted export handling only
with an explicit key-management design. Keep the existing OSCAL Component Definition distinct
from a completed assessment or certification. [Current framework contract](compliance-frameworks.md).

**Safe change preview.** After permission semantics are proven, show the modeled effect of removing
one grant, including alternate paths that retain access. Label it a simulation with coverage limits;
never promise that an untested change cannot disrupt a service.

## Reliability and everyday usability

Reuse the OpenTelemetry Collector where appropriate instead of building every network receiver.
Persistent queues and retries address some restart/outage scenarios but still have disk, capacity,
and retry-limit failure modes. Athena still needs its own acceptance and retention contract;
putting a collector in front of a normalization endpoint does not create durable Athena storage.
[Collector resilience](https://opentelemetry.io/docs/collector/resiliency/).

For the UI, test reviewer and administrator roles separately: keyboard navigation, visible focus,
status announcements, non-color severity cues, session expiry, denied permissions, empty states,
and source outages. The current dashboard loads multiple domains through one `Promise.all`;
evaluate whether an optional security-domain failure should prevent core identity work. This is
a code-based resilience concern, not a reproduced outage. Use WCAG 2.2 as an accessibility test
reference; no conformance claim is made. [Dashboard](../apps/web/src/App.tsx),
[WCAG 2.2](https://www.w3.org/TR/WCAG22/).

Publish a minimal supported deployment with optional Neo4j/AI features, data-flow and credential-scope
explanations, versioned release notes, troubleshooting, and a clear support route. Make the demo
useful without live customer credentials. A hosted service could reduce setup work later, but adds
operational and data-handling responsibilities; no hosting model is selected by this research.

## Delivery sequence and measurable exit gates

These are proposed milestones, not time estimates or achieved metrics.

| Stage | Deliverable | Exit gate |
|---|---|---|
| 1: First useful session | Complete deployment verification, guided read-only onboarding, search, evidence view, one review, export | Three prospective users independently complete a scripted task; record time, errors, and every request for help |
| 2: Trustworthy evidence | Coverage/freshness UI, semantic fixtures, safe identity linking, sync recovery | Every finding links to observed facts and limitations; supported fixtures match provider expectations; partial sync never silently deletes access |
| 3: Repeatable governance | Owner routing, due dates, reminders, exceptions, recurring review, manual fulfillment verification | One pilot team completes a recurring cycle; measure overdue cases, disputed findings, reviewer time, and independently verified outcomes |
| 4: Controlled access lifecycle | Small request catalog and one separately authorized executor, then expiration | In a test tenant, prove approval separation, exact target checks, idempotent retries, failure recovery, and observed expiry/removal |
| 5: Expansion | Pilot-selected connectors, machine workload trust, evidence assistant, additional exports | Each addition improves a measured user task and passes published semantic/security acceptance checks |

Production operational gates run alongside pilot preparation and must close before production
dependence. A pilot with synthetic data does not require pretending that production is ready.

Suggested metrics: time to first useful finding; percentage of findings with current source evidence;
disputed/unsupported findings; review completion and overdue rate; verified-remediation latency;
collection lag and recovery time; repeat weekly use; operating cost at a declared tenant size.
Set numerical performance thresholds with pilot users and measurements rather than inventing them.

## Work to defer and questions to validate

Defer a universal security suite, more policy engines, broad connector count, fully autonomous
remediation, and additional dashboards until the core task is useful. Keep browser/mailbox add-ons
optional unless pilots demonstrate that their correlation materially improves access investigations.
Investigate connector interoperability rather than automatically reimplementing providers; the
companion research records Baton SDK options and maintenance caveats. No dependency choice is made.

Interview administrators, resource owners, and auditors: What access question took hours last week?
Which systems contain the evidence? Who approves corrections? How is removal verified? What would
make a finding untrustworthy? Can read-only deployment be approved? Which export or ticket system
is mandatory? What would justify continued use or payment? Public documentation cannot answer
these questions for Athena's prospective users.

Finally, repair documentation drift before onboarding outsiders. For example,
[the graph guide](attack-paths.md) says stale nodes are not removed automatically, whereas
[`_write_projection`](../apps/api/src/athena/services/attack_paths.py) currently replaces the
tenant's derived graph transactionally. The remaining question is refresh scheduling and visible
freshness, not missing replacement logic. Accurate boundaries are part of the product's value.

## Next concrete implementation scope

Finish the blocked signed-in demo verification, then implement the smallest complete
read-only assessment: connector coverage and freshness, a prioritized identity finding,
owner-assigned review, and a verified evidence export. Validate this with prospective users
before committing to a broad enterprise feature program.
