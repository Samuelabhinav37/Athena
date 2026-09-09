# Cross-source correlation: proposed confirmation contract

Status: the user approved the synthetic Keycloak pilot with two-steward
confirmation on 9 September 2026. Person/link persistence, immutable history and
stewardship API/UI are implemented locally. Migration 20260909_25 has not been
applied to an existing database. Production stewardship is explicitly blocked;
confirmed links cannot authorize access changes or alter review approval rules.

## Existing behavior and first slice

`Identity` currently represents a source account, unique by Athena tenant, source
and external ID. The reviewer registry binds that account to an OIDC issuer and
subject. Non-retain cross-source approval fails closed; it cannot yet establish
whether reviewer and target represent the same person.

`GET /v1/identities/{id}/correlation-candidates` now offers tenant-scoped inspection
under existing viewer authentication. It compares human accounts with the configured
OIDC identity source. Case-insensitive, trimmed ASCII email equality produces a
contact hint only. Names are not matching evidence. Missing/unsupported contact
data, inactive targets and workloads get explicit states. Inactive candidates
remain visible so recycled emails do not become an apparently unique match.

Results are bounded to 50 by default, maximum 200, with stable ordering and
`has_more`. Ambiguity is detected even with limit=1. This is a bounded inspection
endpoint, not an exhaustive inventory; it has no continuation token. No database
writes occur. Responses always report `link_confirmed: false`, and expose neither
confidence probabilities nor an approval recommendation. The identity workspace now includes a candidate panel with explicit ambiguity,
inactive account labels, a bounded expansion from 50 to 200 results, and navigation
to another account's evidence. Requests are cancelled when the selected account
changes. The pilot stewardship panel can propose, confirm, reject and revoke links
for a selected candidate pair. Candidate hints themselves remain unconfirmed.

## Persistent pilot model

Before confirmed links are introduced, Azure synchronization now preflights incoming
user and service-principal IDs against recorded directory authority. Conflicting or
missing authority on an existing account is rejected before ingestion, including
the unchanged-fingerprint checkpoint path. Duplicate account IDs within a snapshot
are also rejected. This preserves current source-account evidence; representing
the same source ID in multiple directories still requires the scoped account model.
Legacy Azure accounts missing directory evidence need separately reviewed recovery;
the collector cannot silently assign an authority to them.
This preflight is a sequential ingestion safeguard, not a database-enforced scoped
account key. Concurrent collector races still require the proposed scoped model
and PostgreSQL concurrency validation before production use.

- Person: tenant-local opaque ID, active status and explicit authoritative source
  reference. Never use email or username as its key. The pilot's authoritative
  uses the approved synthetic Keycloak issuer and immutable account subject as its
  anchor. This choice is limited to the pilot; it is not an HR identity guarantee.
- Account link: person ID, existing provider-account ID, provider authority scope,
  validity interval and current revision. Permit multiple accounts per person,
  including multiple accounts at one provider, but one effective person link per
  account at an instant. Shared accounts remain unsupported for person links.
- Link evidence: immutable proposal/confirmation/rejection/revocation events with
  actor issuer/subject, timestamp, reason, source evidence reference, evidence
  version and expected revision. Corrections revoke one link and confirm another;
  they never rewrite a previous confirmation.
- Workload ownership: a separate relationship and workflow. Do not infer that
  service principals or managed identities are people from matching contact data.

All relationships require composite tenant foreign keys, forced RLS, append-only
event protection and partial uniqueness for current links. Existing provider
accounts, grants, and historical review snapshots remain intact. Authority scope
(for example Entra tenant or OIDC issuer) must be stored explicitly before link
confirmation; the existing generic source label is not sufficient by itself.

## Confirmation and approval boundary

A registered, active administrator proposes a link with evidence independent of
the contact hint. A distinct registered administrator confirms it. The confirmer's
role and both stewards' registry eligibility are checked at confirmation time;
optimistic revisions and row locks protect concurrent confirmation/correction.
Linking accounts is not permission to change provider access.

Before a confirmed link can affect destructive-review self-review checks, the
review must snapshot both target and reviewer person-link IDs and revisions.
Approver independence is checked against those confirmed persons, and unresolved,
expired, disputed or changed links fail closed. A correction requires fresh review
evidence; it must not reinterpret a historical approval or unlock a pending
execution silently. Retain the existing cross-source rejection until this complete
contract and its migrations have passed review and validation.

## Scenarios and acceptance

| Scenario | Required treatment |
|---|---|
| Alice changes her display name | Account identity and confirmed history remain stable |
| Bob receives Alice's old email | Email remains a hint; it cannot transfer a person link |
| Alice has two Entra accounts | Both may link to Alice after independent confirmation |
| Two active directory accounts share an email | Ambiguous candidates; no inferred person |
| A workload has Alice's contact email | Ownership workflow; no person correlation |
| Identical source IDs in different authorities | Distinct account references; explicit scope required |
| Similar account in another Athena tenant | No candidate, link or evidence disclosure |
| Link is corrected while a review is open | New revision invalidates dependent approval evidence |
| Steward attempts to confirm their own proposal | Reject; retain proposal evidence |

Next validation needs disposable PostgreSQL migration/drift/RLS/concurrency tests
and signed-in browser acceptance. Review snapshots now bind target and reviewer
person-link versions and fail closed on changes, expiry and same-person review.
This binding is an additional restriction: it does not lift the existing
cross-source approval block or enable the executor. Acceptance evidence and the
future execution boundary remain prerequisites to broader authorization.
No dependency was added.

## Candidate panel acceptance checklist

Frontend tests and the TypeScript/Vite build pass. No connected browser was
available for visual/keyboard acceptance. When available, verify a single hint,
multiple hints including an inactive account, unsupported workload, missing email,
API failure/retry, more than 50/200 results, and rapid selection changes while a
request is delayed. Confirm account navigation opens the selected account and
that an old response cannot replace the current selection. Verify separate steward
confirmation, rejection, revocation and expired/stale conflicts. No provider-access
operation should be offered.

## Pilot operations and precise limits

Migration 20260909_25 adds persons, person_links and person_link_events with tenant
foreign keys, forced RLS, column-limited runtime updates, immutable evidence triggers
and one proposed/confirmed link per account. Person anchors cannot become another
person's account. Expired links retain their historical status and reserve their
account until explicitly revoked; they are not silently renewed or deleted.

`POST /v1/person-links` accepts a Keycloak anchor ID, supported human account ID,
evidence kind, evidence reference and reason. Evidence kinds are synthetic fixture,
directory administrator attestation and HR record. References are human attestations;
Athena does not fetch or independently validate the referenced documents. Email
matching alone is not an evidence kind. Proposals must be confirmed within 24 hours;
account observations must be fresh. The link validity ends 30 days after proposal.

`POST /v1/person-links/{id}/transition` accepts an expected revision and confirmed,
rejected or revoked action. Revocation is a conservative single-steward action;
replacements require a fresh two-steward proposal. `GET /v1/person-links` requires
account_id and supports limit/offset. Its validity-window flag describes dates only,
not continuing person proof or authority to change access.

The workspace opens stewardship for candidate pairs and shows up to 200 history
records. Manual selection now provides two independent paginated inventories for
the Keycloak anchor and provider account, including accounts with different contact
details. Unsupported and inactive records are disabled; counts still include all
matching inventory records. Pair changes reset stewardship form state. Keycloak authority uses the
configured pilot issuer, while Entra account authority uses collected directory ID.
Real person-directory selection, shared-account classification, changed-authority
recovery and concurrent PostgreSQL validation remain outside the synthetic proof.

Manual selector acceptance: verify keyboard navigation in all three inventory
instances, unique search labels, pagination beyond the first page, no-match/error
states, rapid pair changes, and server rejection when an account changes after
selection. Frontend tests cover pair eligibility and distinctness; the build passes.
Signed-in browser validation remains pending.
