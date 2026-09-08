# P04 connector conformance baseline

This contract describes the repository's implemented subset, tested with synthetic
provider responses. It is not a claim of complete provider authorization coverage.

| Evidence | GitHub | Microsoft Entra / Azure |
|---|---|---|
| Accounts | Organization members; outside collaborators excluded | Users and service principals |
| Membership | Teams and their returned members; parent relationships unresolved | Direct group membership; nested groups not expanded |
| Permissions | Reported highest repository role, marked calculated and incomplete lineage | Assignment action strings at recorded scopes; direct and direct-group paths |
| Overlapping paths | Provider reports highest role; underlying grants cannot be distinguished | Distinct assignments remain separate; removing one preserves a remaining group path |
| Conditions/exclusions | Not evaluated | Nonempty conditions, notActions, or notDataActions reject synchronization |
| Unresolved assignment references | No underlying grant reference available | Missing role/principal rejects synchronization before any projection write |
| Deny, eligibility, activity | Unsupported | Deny assignments, PIM eligibility and activity unsupported |
| Wildcards / resource inheritance | No full lineage expansion | Action strings retained; no wildcard expansion or comprehensive effective-access conclusion |
| Writes and closure verification | No live writes or exact underlying-grant closure guarantee | No live writes or complete effective-access closure guarantee |

## Collection and removal boundaries

GitHub continuations must retain the configured scheme, host, port, and endpoint
path, with no credentials or fragment in the URL. Rejected links are never sent
the token. Both collectors stop on a repeated continuation or 10,000 pages per
endpoint. Empty pages with continuation links are traversed. Malformed pages and
HTTP errors fail collection; no partial snapshot is returned for synchronization.

GitHub only accepts a 304 when it sent an ETag for a cached single-page object
list. Multi-page endpoints are recollected to avoid hiding later-page changes.
The caller's cache is not advanced on collection failure. Azure uses full scans.

GitHub absence detection now applies only to grants whose resource belongs to the
collected organization. Azure absence detection remains subscription-scoped.
Tenant query boundaries apply independently. Unknown/legacy GitHub organization
metadata cannot authorize a removal inference. Azure stores the provider's source
assignment ID for future exact-target review work.

Azure validates unresolved and unsupported assignment evidence before calling
identity synchronization, which commits its own projection. On validation failure,
existing identities, grants, entitlements and the successful checkpoint remain
unchanged. The failed attempt does not refresh successful observation time.
This deliberately rejects the entire unsupported snapshot; it does not silently
omit an assignment and interpret that omission as removal.

## Regression coverage

- Untrusted GitHub continuation scheme, host, port and organization path rejected.
- Empty intermediate pages, repeated links, malformed responses and later-page
  HTTP failures exercised for both collectors.
- GitHub ETag reuse, multi-page refresh, another organization in the same tenant,
  cross-tenant checkpoints/resources, idempotency and actual disappearance covered.
- Azure unresolved principal/definition, unsupported condition/exclusion preserve
  prior projection and checkpoint; overlapping direct/group paths, disappearance,
  idempotency and cross-tenant boundaries covered.

## Remaining collection work

P04 is a conformance baseline, not all of phase 3. Snapshot metadata needs explicit
start/end times, normalization version, completeness and warnings. Provider pages
are not a transactionally consistent snapshot; enumeration churn remains possible.
Transport success alone cannot detect a provider silently omitting records.
Bounded rate-limit retries, persistent resume state, delta reset/replay, unexpected
scope/difference alerts, and deeper permission semantics remain later work.
Connector monitoring must continue to surface failures and stale checkpoints.
