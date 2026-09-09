import { useEffect, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet, apiPost } from "./api";
import type { Principal } from "./types";

type Link = { id: string; status: string; revision: number; expires_at: string; snapshot: unknown; events: unknown[] };

export function PersonLinkPanel({ user, anchorId, accountId }: { user: User; anchorId: string; accountId: string }) {
  const [links, setLinks] = useState<Link[]>([]);
  const [admin, setAdmin] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reason, setReason] = useState("");
  const [reference, setReference] = useState("");
  const [kind, setKind] = useState("synthetic_fixture");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError("");
    void Promise.all([
      apiGet<Link[]>(user, `/v1/person-links?account_id=${accountId}&limit=200`, controller.signal),
      apiGet<Principal>(user, "/v1/auth/me", controller.signal)
    ]).then(([items, principal]) => {
      if (!controller.signal.aborted) { setLinks(items); setAdmin(principal.roles.includes("athena-administrator")); }
    }).catch((caught) => { if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Link history unavailable"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [user, accountId, refresh]);
  async function act(path: string, body: unknown) {
    setLoading(true); setError("");
    try { await apiPost(user, path, body); setRefresh((value) => value + 1); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Link action failed"); setLoading(false); }
  }
  return <section aria-label="Person link stewardship"><h4>Keycloak pilot link stewardship</h4>
    <p>A different registered administrator must confirm independent evidence. Links expire after 30 days and cannot authorize access changes.</p>
    <button disabled={loading} onClick={() => setRefresh((value) => value + 1)}>Reload link history</button>
    {error && <p role="alert">{error}</p>}{loading && <p role="status">Loading link records…</p>}
    {admin && <><label>Independent evidence type<select value={kind} onChange={(event) => setKind(event.target.value)}><option value="synthetic_fixture">Synthetic pilot fixture</option><option value="directory_admin_attestation">Directory administrator attestation</option><option value="hr_record">HR record</option></select></label>
      <label>Evidence reference<input value={reference} maxLength={1000} onChange={(event) => setReference(event.target.value)} /></label>
      <label>Reason<textarea value={reason} maxLength={2000} onChange={(event) => setReason(event.target.value)} /></label>
      <button disabled={loading || reference.trim().length < 10 || reason.trim().length < 10} onClick={() => void act("/v1/person-links", { anchor_id: anchorId, account_id: accountId, evidence_kind: kind, evidence_reference: reference, reason })}>Propose this account link</button></>}
    {!loading && !error && !links.length && <p>No recorded links for this provider account.</p>}
    {links.length === 200 && <p>Showing at most 200 history records. Older records may exist.</p>}
    {links.map((link) => <article key={link.id}><p>{link.status} · Revision {link.revision} · Expires {new Date(link.expires_at).toLocaleString()}</p>
      <details><summary>Exact target and immutable history</summary><pre>{JSON.stringify({ target: link.snapshot, events: link.events }, null, 2)}</pre></details>
      {admin && (link.status === "proposed" ? ["confirmed", "rejected", "revoked"] : link.status === "confirmed" ? ["revoked"] : []).map((action) => <button key={action} disabled={loading || reason.trim().length < 10} onClick={() => void act(`/v1/person-links/${link.id}/transition`, { revision: link.revision, action, reason })}>{action === "confirmed" ? "Confirm as second steward" : action === "rejected" ? "Reject proposal" : "Revoke link"}</button>)}
    </article>)}
  </section>;
}
