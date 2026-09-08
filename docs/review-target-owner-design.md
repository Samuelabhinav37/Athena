# P05 review target and owner design

Status: approved by the user on 8 September 2026. P06 and the initial manual
fulfillment implementation are now locally validated. See
[implementation and remaining acceptance](bound-review-operations.md) for the
implemented scope, migration status, and deliberate coverage limits.

## Problem and intended behavior

Review ownership currently uses a username string, and the API passes
`principal.actor` to decisions. A renamed or recycled username is therefore not a
durable authorization binding. Opening a case currently picks the highest scoring
entitlement and reuses an active case for the whole identity, preventing an exact
finding choice. ReviewCase's evidence constraint requires risk or anomaly evidence.

The proposed review binds one exact target and one eligible immutable reviewer.
For example, two Azure assignments giving Alice the same permission can have
distinct reviews. Removing assignment A does not certify that Alice lost the
permission while assignment B remains.

## Proposed data changes

1. Add a tenant-scoped reviewer registry with immutable `(issuer, subject)`, display
   label, active/eligible state, and eligibility provenance. Require administrator
   registration or an authoritative identity integration; matching a source account
   name/email is insufficient. Unregistered reviewers cannot be assigned cases.
2. Add nullable owner-registry reference and a monotonic revision to ReviewCase.
   Keep the current owner string as a legacy display value. Add opener issuer and
   subject for new cases. Tenant-composite foreign keys enforce registry ownership.
3. Add an immutable target snapshot to the opening event: identity, entitlement,
   finding/evaluation ID, evidence/model/policy versions, source/provider scope,
   permission/resource IDs, source assignment ID where known, collection timestamp,
   coverage limitations, requested action and closure goal. Store a canonical digest.
4. Add actor issuer/subject and target digest to new event evidence. Existing events
   remain unchanged. Add a policy-evaluation reference and extend the evidence
   constraint to permit policy-backed cases without a risk/anomaly run.

Prefer additive nullable columns followed by application enforcement over an
invented backfill. The migration must be forward-only, include RLS/tenant keys and
schema-drift checks, and run against disposable PostgreSQL first. No existing
database migration is authorized by this proposal.

## Legacy compatibility

Old cases and events remain readable with their original display labels and
evidence semantics. Unbound active cases require explicit administrator/reviewer
resolution to a registry entry before a new decision. Do not map legacy owners by
username or email, silently reassign resolved cases, or rewrite past actor values.
Legacy resolved cases cannot become newly executable without fresh target-bound
approval. Existing clients attempting username-only assignment receive a conflict
explaining the required immutable owner ID.

## API and workflow

- Eligible reviewers are listed from the tenant registry. Assignment supplies a
  registry ID, expected case revision and reason; the server validates eligibility.
- Opening supplies the exact finding/evaluation and proposed action/closure goal.
  The server resolves all evidence within the tenant and verifies its identity and
  target relationships. No arbitrary client-supplied evidence snapshot is trusted.
- Duplicate detection keys active work to target plus action, not identity alone.
  The database enforces active-case uniqueness with a suitable partial index.
- Assignment/decision uses a row lock or compare-and-swap revision in the same
  transaction as the append-only event. Stale revisions return 409. Reassignment
  cannot overwrite a concurrently accepted decision.
- Decisions compare authenticated issuer/subject against the active bound owner,
  recheck role and registry eligibility, and verify target/evidence freshness.
  Changed targets require a new review event and approval, not silent substitution.
- Self-review is denied when authoritative identity binding proves the target is
  the reviewer. Ambiguous bindings block destructive approval pending resolution.
  Proposed conservative default: destructive/exception decisions require an
  approver distinct from the opener and fulfillment operator. Product/security
  must confirm independence requirements before enabling that workflow.

For GitHub calculated permission evidence, the target explicitly lacks an exact
underlying assignment. It can support investigation, but cannot authorize an
exact-grant executor. Azure assignment IDs are available in new synchronization
metadata; legacy hashes cannot be guessed back into source assignment IDs.

## P06 implementation and acceptance sequence

1. Add registry/owner/revision/evidence columns with forward migration and tenant
   constraints; verify migration, drift and historical-data preservation locally.
2. Implement registry eligibility resolution and owner/target service contracts.
3. Add exact target selection, immutable reviewer selector and revision conflicts
   to API/UI. Retain read-only legacy history and explicit unresolved-owner state.
4. Test cross-tenant IDs, wrong issuer, reused/renamed username, inactive reviewer,
   unknown owner, changed target, stale revision, two simultaneous decisions,
   prohibited self-review, and policy-only evidence.
5. Run real PostgreSQL concurrency/RLS tests, policy/security gate and signed-in
   synthetic review acceptance before calling the slice complete.

## P07 seam

Manual fulfillment needs its own owner, due date, state and append-only events.
Decision acceptance creates pending work, never verified closure. Verification
must compare the target digest and closure goal against source evidence collected
after the operator's completion timestamp. Outcomes are verified, still present,
collection failed, or insufficient coverage. Alternate access paths matter for
effective-access goals. Case-scoped reports expose those distinctions and retain
the complete event chain.

Implementation requires the applicable auth/model/migration review identified in
AGENTS.md section 10 and the approved plan's P05/P06 gate. This proposal makes
that review concrete; remaining production ownership, deployment, pilot identity
source, and executor scope decisions are not assumed resolved.
