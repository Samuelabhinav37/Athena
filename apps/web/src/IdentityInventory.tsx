import { useEffect, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet, ApiError } from "./api";
import { userManager } from "./auth";
import { INVENTORY_PAGE_SIZE, requestIdentityPage } from "./inventory";
import type { IdentityPage } from "./inventory";
import type { Identity } from "./types";

export function IdentityInventory({ user, selectedId, onSelect }: {
  user: User; selectedId: string; onSelect: (identity: Identity) => void;
}) {
  const [draft, setDraft] = useState("");
  const [request, setRequest] = useState({ query: "", offset: 0, attempt: 0 });
  const [page, setPage] = useState<IdentityPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    setLoading(true); setError(""); setPage(null); setExpired(false);
    return requestIdentityPage(
      (path, signal) => apiGet<IdentityPage>(user, path, signal), request.query, request.offset,
      (result) => { setPage(result); setLoading(false); },
      (caught) => {
        const sessionExpired = caught instanceof ApiError && caught.status === 401;
        setExpired(sessionExpired);
        setError(sessionExpired ? "Your session expired. Sign in again to search identities." : "Identity inventory could not be loaded. Retry the search.");
        setLoading(false);
      }
    );
  }, [request, user]);

  function navigate(offset: number) {
    setLoading(true); setPage(null); setError("");
    setRequest((current) => ({ ...current, offset }));
  }

  return <section className="identity-list" aria-label="Identity inventory" aria-busy={loading}>
    <form className="inventory-search" onSubmit={(event) => {
      event.preventDefault(); setLoading(true); setPage(null); setError("");
      setRequest({ query: draft.trim(), offset: 0, attempt: request.attempt + 1 });
    }}>
      <label htmlFor="identity-search">Search all tenant identities</label>
      <input id="identity-search" className="search" value={draft} maxLength={255} onChange={(event) => setDraft(event.target.value)} placeholder="Name, email, department or source" />
      <button className="button button--secondary" type="submit">Search</button>
    </form>
    {loading && <p role="status">Loading identities…</p>}
    {error && <div role="alert"><p>{error}</p>{expired
      ? <button className="button button--secondary" onClick={() => void userManager.signinRedirect()}>Sign in again</button>
      : <button className="button button--secondary" onClick={() => navigate(request.offset)}>Retry</button>}
    </div>}
    {!loading && page && <>
      <p role="status">{page.items.length ? `${page.offset + 1}–${page.offset + page.items.length}` : "0 shown"} of {page.total} matching identities{request.query ? ` for “${request.query}”` : ""}.</p>
      {!page.items.length && <p>{page.total ? "This page is now empty. Return to the first page to refresh the inventory." : "No matching identities found."}</p>}
      {page.items.map((identity) => <button key={identity.id} className={identity.id === selectedId ? "identity-row selected" : "identity-row"} aria-pressed={identity.id === selectedId} onClick={() => onSelect(identity)}>
        <span className="avatar">{identity.display_name.slice(0, 1)}</span><span><strong>{identity.display_name}</strong><small>{identity.department ?? identity.source} · {identity.username}</small></span><span className={identity.active ? "live-dot" : "live-dot inactive"} />
      </button>)}
      {selectedId && !page.items.some((item) => item.id === selectedId) && <p>The selected identity remains open in the evidence panel; it is outside this results page.</p>}
      <small>Counts reflect matching account records, not people or complete access coverage. Inventory can change between pages.</small>
    </>}
    <nav aria-label="Identity pages">
      <button className="button button--secondary" disabled={loading || request.offset === 0} onClick={() => navigate(Math.max(0, request.offset - INVENTORY_PAGE_SIZE))}>Previous</button>
      <button className="button button--secondary" disabled={loading || !page || page.offset + page.items.length >= page.total || !page.items.length} onClick={() => navigate(request.offset + INVENTORY_PAGE_SIZE)}>Next</button>
      <button className="button button--secondary" disabled={loading || request.offset === 0} onClick={() => navigate(0)}>First page</button>
    </nav>
  </section>;
}
