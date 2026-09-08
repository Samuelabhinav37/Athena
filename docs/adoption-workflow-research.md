# Athena adoption and workflow research

Research date: 2026-09-06. Scope: official documentation and first-party repositories for Microsoft Entra, ConductorOne/Baton, and Veza. This is a product-direction contribution, not a fresh implementation audit. Competitor documentation establishes documented capabilities, not independently measured effectiveness. Recommendations below are proposals and require customer validation.

## What usable identity governance already includes

**Requests must become a complete lifecycle.** Entra documents resource bundles, eligibility rules, multistage approval, time limits, delegated ownership, and recurring reviews. Employees should be able to find the access needed for a task and its responsible approver. This is a stronger baseline than a dashboard of risky identities. [Microsoft entitlement management overview](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview)

**Work must remain understandable after submission.** Microsoft's request process distinguishes submission, pending approval, timeout, approval, and resource assignment; its requester guide covers cancellation, resubmission, and seeing approver information. Athena should expose separate policy eligibility, human approval, execution, and verification states so that an approval cannot be mistaken for effective access. [Request process](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-process), [Requester workflow](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-request-access)

**Review campaigns need people and deadlines.** Entra supports recurring assignment reviews, reviewer justification, notifications, expiration, and reporting. Athena should treat owner assignment, delegation, reminders, overdue cases, and closure evidence as central workflow capabilities. A recommendation without an accountable owner is unlikely to become a completed control. [Access package reviews](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-reviews-create)

**Connector support is resource-specific.** ConductorOne's GCP documentation explicitly distinguishes resources that can be synchronized from those that can be provisioned and differentiates several Google connectors. Its Docusign table documents synchronization without provisioning. A connector count therefore says little about usable governance depth. Athena should publish a per-resource matrix covering discovery, inheritance, effective permissions, activity, execution, verification, and known gaps. [GCP connector](https://www.conductorone.com/docs/baton/google-cloud-platform/), [Docusign connector](https://www.conductorone.com/docs/baton/docusign/)

**A graph needs explicit uncertainty.** Veza's product updates document filters for indirect access, indicators for unsupported policy statements, and metadata refresh attributes. These are concrete product precedents for showing how trustworthy a permission conclusion is. Athena should distinguish direct and inherited paths and show source time, incomplete coverage, unresolved identity joins, and unsupported semantics beside each answer. Do not equate missing data with no access. [Veza April 2024 updates](https://veza.com/blog/veza-product-updates-april-2024/)

## Where Athena can stand out

The repository's AGENTS.md establishes an unusually useful design contract: deterministic versioned policy decisions, advisory models, human approval, and append-only evidence. This is an architectural intention, not proof every deployment satisfies it. Build the initial product around one question: **Why does this person have this permission, what changed, and can we prove the approved correction took effect?**

Proposed differentiation:

1. **Explainable access history:** reconstruct an identity-to-resource path at a selected time, attach source observations and policy versions, and compare changes. Describe unknowns explicitly.
2. **Review-to-verification evidence:** one case links finding, reviewer rationale, approved action, executor result, and independent resynchronization. Keep existing GitHub/Azure collection credentials read-only; a future executor requires separate authorization and credentials.
3. **Useful without write access:** offer a read-only assessment that produces a prioritized review queue and portable evidence. This gives administrators value before they authorize operational changes.
4. **Evidence-grounded assistance:** let natural-language questions retrieve permission paths and evidence references. Measure unsupported-claim frequency; models must not silently infer missing permissions or enact decisions.

These are positioning hypotheses, not claims of uniqueness: Veza already documents effective-permission graphs and Baton supports access-data extraction and comparison.

## Suggested sequence and acceptance measures

| Stage | Proposal | Evidence of usefulness |
| --- | --- | --- |
| First usable release | Guided read-only onboarding for existing sources, connector health/coverage, identity search, one complete review and evidence export | New administrator completes setup and first review without developer help; every finding identifies its source and freshness |
| Operational pilot | Ownership/delegation, reminders, expiring exceptions, durable collection and retry visibility, ticket handoff | Track completion rate, reviewer time, stale observations, disputed findings, and verification latency |
| Controlled execution | Separately authorized executor, precondition checks, idempotency, partial-failure recovery, reconciliation, then time-bound requests | Demonstrate approved action and expiry in a test tenant; prove effective state through new observations |
| Expansion | Add connectors selected by pilot demand; govern service accounts with owners and lifecycle context | New sources meet published semantic coverage criteria; nonhuman accounts have accountable owners |

Targets should be set with pilot users; no numeric adoption or performance claims have been established. Recruit identity administrators, resource owners, and auditors for task-based trials, and record where they need help. Public documentation cannot establish willingness to pay or which missing integrations dominate Athena's target market.

## Connector ecosystem caveat

Investigate a read-only Baton import adapter before rebuilding every connector, but validate licensing, provenance, identity mapping, completeness, and format/version compatibility first. The original `ConductorOne/baton` repository is archived and explicitly redirects active development to `baton-sdk`; do not propose the retired repository as an actively maintained dependency. No dependency was installed or integration proven in this research. [Retired Baton repository](https://github.com/conductorone/baton), [Current SDK repository](https://github.com/conductorone/baton-sdk)

Verification: opened official sources and checked citations; documentation-only change. No application tests, live connectors, external writes, or runtime verification were performed.
