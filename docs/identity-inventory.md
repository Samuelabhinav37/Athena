# Identity inventory — P03

The Identity evidence screen searches the tenant's stored account inventory on
the server and displays 50 records per page. Search is submitted with the Search
button or Enter. A new search starts at the first page. Previous, Next, and First
page controls navigate the results.

## API contract

`GET /v1/identities/inventory?q=engineering&limit=50&offset=200`

The viewer-authorized response contains `items`, `total`, `limit`, and `offset`.
`items` uses the existing identity response shape. `total` counts matching account
records in the validated tenant, including inactive accounts. It does not count
unique people, entitlements, or prove collection completeness.

Search trims whitespace and matches a case-insensitive literal substring against
username, display name, email, department, source, or external ID. `%` and `_`
are literal characters, not search wildcards. Database collation governs Unicode
case behavior. Query length is bounded to 255 characters; limit is 1–200 and
offset is nonnegative. Empty search returns all scoped accounts.

Results sort by username and then immutable identity ID, so duplicate usernames
do not cause ambiguous page boundaries. A window count shares the database
snapshot with each nonempty page. An empty page performs a separate scoped count
to distinguish no matches from an offset beyond current results.

The existing `GET /v1/identities` array response remains compatible. The new route
is registered before the UUID detail route. No schema migration is required.

## Interaction and failure behavior

- The selected identity remains open when results or pages change. The list
  identifies when that account is outside the displayed page.
- Choosing an account clears the prior detail display while its evidence loads.
  A late AI explanation for a previous selection cannot replace the new selection.
- Review creation carries the selected account into the existing review selector,
  including accounts absent from the dashboard's initial inventory page.
- Cancelled and unmounted searches cannot replace results or display late errors.
- Loading, no matches, an empty page after inventory changes, and request errors
  have distinct states. Errors do not display a zero matching count.
- Expired sessions offer the existing sign-in flow. Other errors offer Retry.
  Paging buttons stay mounted while requests run. Inputs and buttons use native
  keyboard semantics; results/loading use status announcements.

## Validation and remaining limits

API regression tests exercise 205 records, a match beyond the first 200 records,
literal wildcards, duplicate usernames, empty pages, bounds, and tenant isolation
for both results and counts. Frontend request tests exercise encoded search,
page offsets, cancelled responses, unmounts, and 401/403/503 propagation.

Offset pagination is a live view, not a frozen export: collection changes between
requests can move records across page boundaries. First page and search refresh
the view. Large-tenant performance has not been benchmarked; substring searches
and counts may require future indexing based on measured workloads.

Signed-in browser acceptance remains pending because no connected browser was
available during implementation. Check Enter-to-search, Tab navigation through
page controls, screen-reader announcements, selecting an account on the last
page and opening its review, retry/sign-in interactions, and narrow-screen layout
against synthetic data. PostgreSQL runtime validation also remains pending while
the Docker engine is unavailable. Unit tests do not substitute for these checks.

Overview, setup coverage, review queues, machine identities, and selected-account
detail lists retain their existing bounded-page behavior. This patch expands the
identity inventory only; the global loaded-page caveat still applies elsewhere.
