# How comparable platforms solve Athena's identity-governance problems

Research date: 8 September 2026. This expands the [7 September comparison](athena-competitor-research-2026-09-07.md) with mechanisms, operational boundaries, and a shared example. Sources are official documentation and public vendor SDKs; no commercial tenant was exercised. Product behavior depends on enabled features, configured policies, and the specific connector. Proprietary backend implementation details, production accuracy, and comparative reliability are not established by these sources.

## The main result

The useful pattern is to maintain several distinct facts: **who the identity is, what access is observed, what access is intended, what a reviewer authorized, what the executor attempted, and what the source subsequently shows**. Combining these into a single “approved” or “healthy” status makes failures hard to understand.

The four platforms emphasize different parts of this problem. Microsoft Entra coordinates directory-connected access lifecycles; SailPoint provides identity correlation and a business access model; C1/ConductorOne standardizes connectors and access workflows; Veza models authorization relationships and permissions. These are explanatory emphases, not exclusive capabilities or a vendor ranking.

## 1. Microsoft Entra: govern assignments and operate a synchronization service

### How the parts fit

An **access package** bundles resource roles needed for a task. Policies specify eligible requesters, approvers, and assignment duration; catalogs let resource owners administer related packages. This gives an employee a business-facing unit of access while retaining the underlying resource assignments. [Entitlement-management model](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview).

Requests have separate submission, approval, and delivery states. An approved request can still be delivering or partially delivered before all assignments are complete. The system also records denial, approval timeout, extension, and assignment expiry, with notifications. The separation is important for Athena: approval is a decision; delivery is an operational result. [Request process](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-process).

For application provisioning, Entra uses a target SCIM API or provisioning agent. Initial synchronization applies scope and attribute mappings, matches target accounts, retains target identifiers, and saves a watermark. Later cycles process changes; retryable target failures are retried, while widespread failures can quarantine the job. Operators must fix configuration or source-data problems rather than expect retries to repair everything. This describes application provisioning, not every Entra governance operation or a universal cloud-permission reconciler. [Provisioning mechanism](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/how-provisioning-works).

### How access risk is reduced

PIM separates **eligible** from **active** privileged assignments. Activation can require approval, MFA, and justification and lasts for a configured period. This reduces permanent privileged access where PIM manages the assignment. It is a different capability from Athena evaluating observed access through OPA. [PIM concepts](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure).

Completed access reviews have a separate apply-results step. Microsoft documents important exceptions: on-premises-managed memberships cannot be changed there, and nested or group-derived access can remain after a denial. The source of authority determines where removal must occur. [Applying review results and limitations](https://learn.microsoft.com/en-us/entra/id-governance/complete-access-review).

Configured accidental-deletion thresholds quarantine unusually large disable/delete batches for administrator investigation. This is a concrete defense against a bad scoping change producing mass removal. [Deletion protection](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/accidental-deletions).

### What Athena should learn

Use distinct decision, delivery, and observed-outcome states; persist target identity and synchronization progress; surface partial delivery and configuration failures; and model eligibility separately from active permission if PIM evidence is added. Any future bulk executor needs a reviewed safety threshold. Athena should preserve its human-approval boundary rather than automatically copy another platform's execution policy.

## 2. SailPoint Identity Security Cloud: connect accounts to people and enforce an access model

This section concerns Identity Security Cloud, not the separately deployed IdentityIQ product. Claims about one should not be transferred to the other.

### How the parts fit

An **authoritative source**, such as HR or a directory, creates the identity population through an identity profile. The profile maps identity attributes and lifecycle behavior. Priority resolves which profile governs an identity that appears in multiple authoritative sources. Missing required identity data produces exceptions for an operator to resolve. [Identity profiles](https://documentation.sailpoint.com/saas/help/setup/identity_profiles.html).

**Account correlation** maps application accounts to those identities using configured attribute comparisons. Unmatched accounts remain uncorrelated; testing and manual resolution are available. This is an explicit data-quality task, not an assumption that every matching display name or email must represent the same person. [Correlation](https://documentation.sailpoint.com/saas/help/accounts/correlation.html).

An **access profile** bundles entitlements from one source. Roles and lifecycle states use these bundles, while access requests can grant them too. Origin affects removal: a role-derived profile cannot simply be revoked independently, and a role can preserve permissions overlapping a revoked profile. Other overlapping-profile behavior differs, so a universal “remove one bundle, keep all other access” rule would be unsafe. [Access-profile model and removal semantics](https://documentation.sailpoint.com/saas/help/access/access-profiles.html).

Configured role criteria can assign access based on attributes such as department. When an identity no longer qualifies, its role and associated profiles are deprovisioned. Removing those permissions does not itself delete the source account. [Role assignment](https://documentation.sailpoint.com/saas/help/provisioning/role_assignment.html).

### How drift and operational failure are handled

Native Change Detection compares newly aggregated account data with stored data to find monitored changes made outside SailPoint. These events can trigger workflows. It requires aggregation and configured monitored operations/attributes; it is not universal instantaneous observation of every application event. [Native changes](https://documentation.sailpoint.com/saas/help/sources/native_change_detection.html).

Provisioning can run through a direct connector or become a manual task, depending on the source capability. Certain recognized connectivity failures are retried hourly up to three times; queued work can delay the schedule. A configured manual path therefore remains useful when automatic writes are unavailable. [Provisioning and retries](https://documentation.sailpoint.com/saas/help/provisioning/index.html).

Operators can reassign manual tasks and inspect provisioning/account activity, stages, and errors. A person marking a task complete is a workflow event; the cited monitoring page does not establish universal independent permission read-back after every completion. [Operational tracking](https://documentation.sailpoint.com/saas/help/provisioning/tracking.html).

Lifecycle configuration can remove access or disable/delete accounts, but retained birthright access and current lifecycle requirements matter. Required access can be provisioned again while its assignment rule still applies. Some termination removal modes bypass removal approval; Athena's current human-approval contract should not inherit that behavior implicitly. [Lifecycle semantics](https://documentation.sailpoint.com/saas/help/provisioning/lifecycle.html).

### What Athena should learn

Create an explicit, reviewable cross-source identity-linking model; preserve which rule, role, group, or request caused access; and make corrective action target that origin. Support owned manual fulfillment and fresh observation of its outcome. Model out-of-band changes as evidence that can open a case. Scope changes to Athena's identity or review model would require their own implementation and migration review.

## 3. C1/ConductorOne: standardize connectors and make access work recoverable

Baton separates **resources**, **entitlements**, and **grants**. Its staged SDK discovers objects, their assignable access, and the principals holding that access. Stable native identifiers connect observations across scans. [Connector concepts](https://www.c1.ai/docs/developer/concepts).

Pagination uses explicit continuation state, including nested traversal state. An empty page with a continuation token is not completion. Incremental sync remains connector-specific; a page cursor is not automatically a change-feed cursor. [Pagination](https://www.c1.ai/docs/developer/pagination), [an Azure DevOps incremental implementation](https://www.c1.ai/docs/baton/azure-devops/).

Request, review, and revoke policies are separate. Ordered rule matching chooses the workflow, which can include distinct approvers, justification, and overdue-task handling. [Policy mechanism](https://www.c1.ai/docs/product/admin/policies).

Grant/revoke interfaces receive specific access objects, with target assignment IDs and already-present/already-removed outcomes supporting precise, retry-safe operations. Daemon workers poll, heartbeat, and report completion; lost heartbeats can lead to reassignment. [Provisioning](https://www.c1.ai/docs/developer/provisioning), [task protocol](https://www.c1.ai/docs/developer/c1-api).

**Lesson for Athena:** connector behavior should be a testable protocol, and an execution needs durable ownership, exact targets, attempts, and recovery. Worker reassignment alone cannot guarantee exactly-once provider writes. Preserve human authorization and reconcile ambiguous outcomes before a retry. The [technical companion](athena-c1-veza-mechanisms-2026-09-08.md) gives detailed examples and limits, including why resource containment does not automatically establish inherited access.

## 4. Veza: normalize permission meaning and keep visibility separate from writes

OAA represents local/federated identities, groups, roles, resources, and scoped permissions. Integrators map source-native actions into canonical permission categories. Accurate graph answers depend on accurate source translation. [Permission model](https://developer.veza.com/oaa/guide/core-concepts/modeling-users-permissions-and-roles).

Explicit identity references link application accounts to IdP objects. An unresolved link produces a warning while retaining the local account, preserving useful observations without claiming a known owner. [Cross-service identity links](https://developer.veza.com/oaa/guide/core-concepts/cross-service-connections).

A full initial push establishes the graph baseline. Later incremental payloads describe explicit changes; reliable full extraction is recommended when change tracking is unavailable. Metadata deletion changes the graph, not the upstream account. [Incremental ingestion](https://developer.veza.com/oaa/reference/incremental-updates).

OAA visibility and SCIM lifecycle operations are configured separately and require consistent identity objects. Deactivation and deletion are distinct source operations. [OAA/SCIM integration](https://developer.veza.com/oaa/guide/core-concepts/oaa-scim).

**Lesson for Athena:** retain source-native permission meaning alongside normalized categories, preserve unresolved identity links, and clearly separate evidence updates from source changes. A graph is useful only to the extent its paths, source scope, and freshness are trustworthy. These public interfaces do not establish Veza's proprietary graph engine internals or universal post-write verification.

## 5. One shared example: Alice moves from Finance to Engineering

This is an illustrative comparison of the documented mechanisms, not a test run or a claim that any product automatically solves an unconfigured scenario.

| Step | Question the system must answer | Why this matters for Athena |
|---|---|---|
| Establish identity | Is the HR record the same person as the GitHub and cloud accounts? | A wrong join can misattribute access or send work to the wrong owner |
| Observe the change | Which job attribute changed, and when was that observed? | Provider-effective time and collection time are different facts |
| Re-evaluate entitlement origin | Does Payroll access come from a finance role, nested group, direct grant, or exception? | Each origin can require a different correction |
| Decide | Is the access still allowed, and who is authorized to approve correction? | A policy result and a recorded human decision have different authority |
| Fulfill | Which specific source operation, or manual owner, can remove the unwanted path? | Read support does not imply write support |
| Observe again | Did the target grant disappear, and does another path still give Payroll access? | Removing one assignment does not prove loss of effective access |
| Preserve | Which source observations, policy version, approval, attempts, and outcome support closure? | A review must remain understandable after the operator leaves |

For Entra, configured assignments, package lifecycle, or reviews can drive the correction, but the origin and target connector constrain fulfillment. For SailPoint, a department change can cause the person to stop qualifying for the finance role; an independent direct grant still requires its own investigation. These examples follow the mechanisms cited in sections 1 and 2, rather than assuming every source or permission is covered.

For C1, a connector can observe the changed membership and a configured workflow can route a specific access removal to a connector task. For Veza, the changed group/role relationship changes the represented permission paths; a separately configured write integration handles source changes. Suppose Alice also has a direct Payroll grant: removing the Finance group path alone cannot satisfy a goal of eliminating all Payroll access. This is a logical consequence of the example, not an untested assertion about an automatic vendor feature.

## 6. Comparing the mechanisms against our actual questions

| Athena question | Strongest lesson from this research | What must still be proved |
|---|---|---|
| Who is this person across applications? | SailPoint's explicit correlation and Veza's retained unresolved accounts | Ambiguous/recycled identifiers must not silently merge people |
| Why does this permission exist? | SailPoint's access origin and Veza's scoped permission model | Supported inheritance and overlapping paths must match provider semantics |
| How do we notice changes reliably? | Entra's watermark cycles, C1's traversal state, and Veza's baseline/delta distinction | Completeness, deletions, replay, and failure recovery on each actual source |
| How do people finish governance work? | Entra's separate delivery states and C1's workflow routing | Correct owner, target, deadline, escalation, and user-visible failure |
| What if the source cannot be changed automatically? | SailPoint's owned manual provisioning path | Manual completion needs fresh evidence before claiming effective removal |
| How do we recover from interruptions? | C1's task heartbeats and Entra's quarantine mechanisms | No unreviewed target changes or blind replay after an ambiguous write |

This table is an engineering synthesis of the cited mechanisms, not a completeness ranking. Competitors overlap substantially in functionality.

## 7. What this changes in our understanding of Athena

Athena already has useful pieces: a normalized evidence store, source/external identifiers, ordered provenance, versioned policy evaluations, owned review cases, and an execution contract. The current [models](../apps/api/src/athena/models.py), [connector contract](../apps/api/src/athena/collectors/contracts.py), [review service](../apps/api/src/athena/services/remediation.py), and [execution service](../apps/api/src/athena/services/execution.py) establish those boundaries.

The research suggests these requirements before broadening the product:

1. **Person and account must be distinguishable.** Linking multiple provider accounts to one person needs explicit rules, confidence/provenance, ambiguity handling, and correction history. It must not silently merge accounts on display names.
2. **Observed access and intended access must be distinct.** A role or request can establish why access is desired, while a collector establishes what was observed. Their disagreement is valuable evidence.
3. **Permission origin determines remediation.** A graph needs more than a path visualization: it must tell the reviewer whether the controlling object is a group, role assignment, direct grant, or a different source of authority.
4. **Synchronization is a product capability.** Complete snapshots, cursor validity, resumable pages, provider throttling, partial observations, and operator recovery need explicit contracts.
5. **A case needs separate outcomes.** Requested, approved, executing, manual action needed, failed, verification pending, and observed complete should not collapse into “resolved.” Exact state names and migration design remain future work.
6. **A source operation and effective access are different.** Store both the operation result and the fresh permission evidence. If coverage cannot prove complete removal, show that limitation.

These are engineering conclusions from the comparison. They do not assert that every competitor provides the same guarantees or that Athena lacks all of these concepts today.

## Research limits and next validation

The review establishes documented interfaces and behavior, not proprietary storage architecture, accuracy benchmarks, customer configuration, licensing suitability, or independently tested security. No universal claim that all four vendors verify effective access after every removal was established.

Before selecting an integration or copying a workflow, a controlled proof should exercise: an ambiguous person/account match; a nested or overlapping access path; a partial snapshot; a source rate limit; an approval followed by changed source state; a completed manual task whose access remains; and an unavailable connector. Each case should declare expected observations and preserve existing human approval for destructive changes.

This task produces research documents only. It does not change Athena application code, policies, credentials, deployment configuration, databases, or access. Earlier application test findings are not repaired or reclassified by this research.
