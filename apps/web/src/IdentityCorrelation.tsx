import { useEffect, useRef, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet } from "./api";
import type { Identity } from "./types";
import { PersonLinkPanel } from "./PersonLinkPanel";
import { ManualPersonPair } from "./ManualPersonPair";

type Candidate = {
  identity_id: string; source: string; external_id: string;
  display_name: string; active: boolean;
};
type Inspection = {
  identity_id: string; state: string; authoritative_source: string;
  candidates: Candidate[]; has_more: boolean; limitations: string[];
};

const descriptions: Record<string, string> = {
  candidate: "Possible account relationship. Matching contact details need independent confirmation.",
  ambiguous: "Multiple accounts share this contact hint. No person relationship is established.",
  unlinked: "No matching contact hints were found. This does not prove the accounts belong to different people.",
  insufficient_evidence: "There is not enough supported contact evidence to suggest accounts.",
  inactive_account: "This account is inactive. Candidate inspection is unavailable.",
  unsupported_account_type: "Non-human accounts need workload ownership evidence instead of person correlation."
};

export function IdentityCorrelation({ user, identityId, source, onSelect }: {
  user: User; identityId: string; source: string; onSelect: (identity: Identity) => void;
}) {
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [error, setError] = useState("");
  const [limit, setLimit] = useState(50);
  const [attempt, setAttempt] = useState(0);
  const [opening, setOpening] = useState(false);
  const [manual, setManual] = useState(false);
  const [pair, setPair] = useState<{ anchorId: string; accountId: string } | null>(null);
  const selection = useRef<AbortController | null>(null);
  useEffect(() => () => selection.current?.abort(), []);
  useEffect(() => {
    const controller = new AbortController();
    setInspection(null); setError("");
    void apiGet<Inspection>(user, `/v1/identities/${identityId}/correlation-candidates?limit=${limit}`, controller.signal)
      .then((result) => { if (!controller.signal.aborted) setInspection(result); })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Candidate inspection unavailable");
      });
    return () => controller.abort();
  }, [user, identityId, limit, attempt]);

  async function inspectAccount(id: string) {
    selection.current?.abort();
    const controller = new AbortController();
    selection.current = controller;
    setOpening(true); setError("");
    try {
      const identity = await apiGet<Identity>(user, `/v1/identities/${id}`, controller.signal);
      if (!controller.signal.aborted) onSelect(identity);
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : "Account evidence unavailable");
    } finally {
      if (!controller.signal.aborted) setOpening(false);
    }
  }

  return <section className="panel" aria-label="Possible related accounts">
    <h3>Possible related accounts</h3>
    <p>Contact hints only. No confirmed person links or changes to access.</p>
    <button onClick={() => setManual((value) => !value)} aria-expanded={manual}>{manual ? "Close manual account selection" : "Select accounts without matching contact hints"}</button>
    {manual && <ManualPersonPair user={user} />}
    {error && <p role="alert">{error} <button onClick={() => setAttempt((value) => value + 1)}>Retry inspection</button></p>}
    {!inspection && !error && <p role="status">Loading candidate accounts…</p>}
    {inspection && <>
      <p role="status">{descriptions[inspection.state] ?? "Correlation status is unavailable."}</p>
      <p>Reference account source: {inspection.authoritative_source}. Showing {inspection.candidates.length} candidate accounts.</p>
      {inspection.candidates.length > 0 && <ul>{inspection.candidates.map((candidate) => <li key={candidate.identity_id}>
        <strong>{candidate.display_name}</strong> · {candidate.source} · {candidate.active ? "Active" : "Inactive"}
        <p>Provider account ID: {candidate.external_id}. Reason: matching contact hint.</p>
        <button disabled={opening} onClick={() => void inspectAccount(candidate.identity_id)}>Inspect account evidence</button>
        {(source === "keycloak" || candidate.source === "keycloak") && <button onClick={() => setPair(source === "keycloak" ? { anchorId: identityId, accountId: candidate.identity_id } : { anchorId: candidate.identity_id, accountId: identityId })}>Inspect person link stewardship</button>}
      </li>)}</ul>}
      {inspection.has_more && <p>More candidates exist than are shown. This list cannot establish uniqueness. {limit < 200 ? <button onClick={() => setLimit(200)}>Show up to 200 candidates</button> : "The 200-account inspection limit has been reached."}</p>}
      <details><summary>Evidence limitations</summary><ul>{inspection.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details>
    </>}
    {pair && <PersonLinkPanel key={`${pair.anchorId}:${pair.accountId}`} user={user} {...pair} />}
  </section>;
}
