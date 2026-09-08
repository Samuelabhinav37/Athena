import { useState } from "react";
import type { User } from "oidc-client-ts";
import { apiPost } from "./api";
import { orderReviews } from "./assessment";
import type { Execution, Identity, Principal, ReviewCase } from "./types";

export function ReviewWorkspace({ user, principal, reviews, identities, initialIdentityId, initialReviewId, onReviewsChanged, onExecutionCreated, onInspect, onExport }: {
  user: User; principal: Principal | null; reviews: ReviewCase[]; identities: Identity[];
  initialIdentityId: string; initialReviewId: string;
  onReviewsChanged: (reviews: ReviewCase[]) => void; onExecutionCreated: (execution: Execution) => void;
  onInspect: (id: string) => void; onExport: () => void;
}) {
  const [identityId, setIdentityId] = useState(initialIdentityId || identities[0]?.id || "");
  const [selectedId, setSelectedId] = useState(initialReviewId || reviews.find((item) => item.identity_id === initialIdentityId)?.id || orderReviews(reviews)[0]?.id || "");
  const [owner, setOwner] = useState("");
  const [dueDays, setDueDays] = useState(7);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const roles = principal?.roles ?? [];
  const canOpen = roles.some((role) => ["athena-analyst", "athena-reviewer", "athena-administrator"].includes(role));
  const selected = reviews.find((item) => item.id === selectedId);
  function accept(review: ReviewCase) {
    onReviewsChanged([review, ...reviews.filter((item) => item.id !== review.id)]);
    setSelectedId(review.id);
  }
  async function openCase() {
    if (pending || !identityId) return;
    setPending(true); setError("");
    try {
      accept(await apiPost<ReviewCase>(user, "/v1/reviews", { identity_id: identityId, owner: owner.trim() || null, due_days: dueDays }));
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not open review"); }
    finally { setPending(false); }
  }
  return <div className="page assessment-reviews">
    <section className="page-heading"><div><p className="kicker">Human review</p><h1>Review access with evidence.</h1></div><p className="heading-note">A recorded decision does not mean access changed. Execution and verification remain separate.</p></section>
    {canOpen && <section className="panel review-create"><h2>Open an evidence review</h2><p>The case uses the latest recorded risk or anomaly evidence. An existing active case is reopened for viewing, not duplicated.</p>
      <form onSubmit={(event) => { event.preventDefault(); void openCase(); }}>
        <label>Identity<select value={identityId} onChange={(event) => setIdentityId(event.target.value)} required>{!identities.length && <option value="">No identities loaded</option>}{identities.map((identity) => <option value={identity.id} key={identity.id}>{identity.display_name} · {identity.source}</option>)}</select></label>
        <label>Suggested owner<input value={owner} maxLength={255} onChange={(event) => setOwner(event.target.value)} placeholder="Optional username" /></label>
        <label>Due in days<input type="number" min={1} max={90} value={dueDays} onChange={(event) => setDueDays(Number(event.target.value))} required /></label>
        <button className="button button--primary" disabled={pending || !identityId}>{pending ? "Opening…" : "Open or view review"}</button>
      </form>{error && <p role="alert" className="notice notice--error">{error}</p>}
    </section>}
    <div className="review-workspace"><section className="panel review-queue" aria-label="Review queue"><h2>Cases in loaded page</h2><p>Active cases first, earliest deadline first.</p>
      {orderReviews(reviews).map((review) => <button key={review.id} className={review.id === selectedId ? "review-choice selected" : "review-choice"} onClick={() => setSelectedId(review.id)} aria-pressed={review.id === selectedId}>
        <strong>{review.title}</strong><span>{review.owner ?? "Unassigned"} · {review.status.replaceAll("_", " ")}</span><time>Due {new Date(review.due_at).toLocaleString()}</time>
      </button>)}{!reviews.length && <p>No reviews recorded. Inspect an identity’s risk or anomaly evidence before opening a case.</p>}
    </section>
      {selected ? <ReviewDetail key={selected.id} user={user} principal={principal} review={selected} onChanged={accept} onExecutionCreated={onExecutionCreated} onInspect={onInspect} onExport={onExport} /> : <section className="panel review-detail"><p>Select a review to inspect its evidence and history.</p></section>}
    </div>
  </div>;
}

function ReviewDetail({ user, principal, review, onChanged, onExecutionCreated, onInspect, onExport }: {
  user: User; principal: Principal | null; review: ReviewCase; onChanged: (review: ReviewCase) => void;
  onExecutionCreated: (execution: Execution) => void; onInspect: (id: string) => void; onExport: () => void;
}) {
  const [owner, setOwner] = useState(review.owner ?? principal?.username ?? "");
  const [reason, setReason] = useState("");
  const [decision, setDecision] = useState("retain");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const roles = principal?.roles ?? [];
  const canReview = roles.some((role) => ["athena-reviewer", "athena-administrator"].includes(role));
  const canDecide = canReview && review.owner === principal?.username && review.status === "in_review";
  const isAdmin = roles.includes("athena-administrator");
  async function act(action: "assign" | "decide") {
    if (pending) return;
    setPending(true); setError(""); setMessage("");
    try {
      const updated = await apiPost<ReviewCase>(user, `/v1/reviews/${review.id}/${action}`, action === "assign" ? { owner: owner.trim(), reason: reason.trim() } : { decision, reason: reason.trim() });
      onChanged(updated); setReason(""); setMessage(action === "assign" ? "Assignment recorded." : "Decision recorded. Upstream access has not been changed by this action.");
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Review action failed"); }
    finally { setPending(false); }
  }
  async function requestExecution() {
    if (pending) return;
    setPending(true); setError(""); setMessage("");
    try {
      const execution = await apiPost<Execution>(user, "/v1/executions", { case_id: review.id, idempotency_key: `ui-${review.id}-revoke` });
      onExecutionCreated(execution); setMessage(`Execution request recorded: ${execution.status}. Check execution evidence for the verified outcome.`);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Execution request failed"); }
    finally { setPending(false); }
  }
  return <section className="panel review-detail" aria-label="Selected review">
    <p className="kicker">{review.status.replaceAll("_", " ")}</p><h2>{review.title}</h2><p>Owner: {review.owner ?? "Unassigned"} · Due {new Date(review.due_at).toLocaleString()}</p>
    <div className="review-links"><button className="button button--secondary" onClick={() => onInspect(review.identity_id)}>Inspect identity evidence</button><button className="button button--secondary" onClick={onExport}>Export tenant evidence</button></div>
    <details><summary>Evidence references captured by this case</summary><dl className="review-references"><dt>Identity</dt><dd>{review.identity_id}</dd><dt>Entitlement</dt><dd>{review.entitlement_id ?? "Not linked"}</dd><dt>Risk assessment</dt><dd>{review.risk_assessment_id ?? "Not linked"}</dd><dt>Anomaly result</dt><dd>{review.anomaly_result_id ?? "Not linked"}</dd></dl><p>The identity view shows current evidence; these references identify the evidence attached to the case when opened.</p></details>
    {error && <p role="alert" className="notice notice--error">{error}</p>}{message && <p role="status">{message}</p>}
    {canReview && review.status !== "resolved" && <div className="review-form">
      <label>Owner username<input value={owner} onChange={(event) => setOwner(event.target.value)} maxLength={255} /></label>
      <label>Evidence-based reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={2000} rows={3} /></label>
      <button className="button button--secondary" disabled={pending || !owner.trim() || !reason.trim()} onClick={() => void act("assign")}>{review.status === "open" ? "Assign review" : "Reassign review"}</button>
      {canDecide ? <><label>Decision<select value={decision} onChange={(event) => setDecision(event.target.value)}><option value="retain">Retain</option><option value="revoke">Revoke</option><option value="extend">Extend</option><option value="exception">Exception</option></select></label><p>A decision requires at least 10 characters of justification.</p><button className="button button--primary" disabled={pending || reason.trim().length < 10} onClick={() => void act("decide")}>Record decision</button></> : <p>Only the assigned owner with reviewer permissions can decide an assigned case.</p>}
    </div>}
    {!canReview && <p>A reviewer must assign and decide this case.</p>}
    {review.resolution && <p><strong>Recorded resolution: {review.resolution}.</strong> Consult execution evidence before treating an access change as completed.</p>}
    {isAdmin && review.status === "resolved" && review.resolution === "revoke" && <button className="button button--secondary" disabled={pending} onClick={() => void requestExecution()}>Request separately authorized execution</button>}
    <h3>Decision and assignment history</h3><ol className="review-history">{[...review.events].sort((a, b) => Date.parse(a.occurred_at) - Date.parse(b.occurred_at)).map((event) => <li key={event.id}>
      <strong>{event.action} · {event.actor}</strong><time>{new Date(event.occurred_at).toLocaleString()}</time><p>{event.reason}</p><small>Execution status at this event: {event.execution_status.replaceAll("_", " ")}</small>
      <details><summary>Evidence snapshot at this event</summary><pre>{JSON.stringify(event.evidence_snapshot, null, 2)}</pre></details>
    </li>)}</ol>
  </section>;
}
