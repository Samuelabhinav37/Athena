import { useEffect, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet, apiPost } from "./api";
import { manualWork, orderReviews } from "./assessment";
import type { Execution, Identity, Principal, ReviewCase } from "./types";

type Reviewer = { id: string; identity_id: string; issuer: string; subject: string; display_name: string; active: boolean };
type Choice = { id: string; kind: "risk" | "policy"; label: string };
type CollectionStatus = { state: string; attempts: number; max_attempts: number; next_retry_at: string | null; outcome: string | null };

export function ReviewWorkspace({ user, principal, reviews, identities, initialIdentityId, initialReviewId, onReviewsChanged, onInspect }: {
  user: User; principal: Principal | null; reviews: ReviewCase[]; identities: Identity[];
  initialIdentityId: string; initialReviewId: string;
  onReviewsChanged: (reviews: ReviewCase[]) => void; onExecutionCreated: (execution: Execution) => void;
  onInspect: (id: string) => void; onExport: () => void;
}) {
  const [identityId, setIdentityId] = useState(initialIdentityId || identities[0]?.id || "");
  const [selectedId, setSelectedId] = useState(initialReviewId || orderReviews(reviews)[0]?.id || "");
  const [reviewers, setReviewers] = useState<Reviewer[]>([]);
  const [choices, setChoices] = useState<Choice[]>([]);
  const [choiceId, setChoiceId] = useState("");
  const [proposal, setProposal] = useState("retain");
  const [goal, setGoal] = useState("assignment_removed");
  const [pending, setPending] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [registerId, setRegisterId] = useState("");
  const [registerReason, setRegisterReason] = useState("");
  const roles = principal?.roles ?? [];
  const canOpen = roles.some((role) => ["athena-analyst", "athena-reviewer", "athena-administrator"].includes(role));
  const isAdmin = roles.includes("athena-administrator");
  const selected = reviews.find((item) => item.id === selectedId);
  useEffect(() => {
    const controller = new AbortController();
    apiGet<Reviewer[]>(user, "/v1/reviewers?limit=200", controller.signal)
      .then(setReviewers).catch(() => { if (!controller.signal.aborted) setError("Reviewer registry unavailable. Retry by reopening this workspace."); });
    return () => controller.abort();
  }, [user]);
  useEffect(() => {
    const controller = new AbortController();
    setChoices([]); setChoiceId(""); setLoading(true); setError("");
    if (!identityId) { setLoading(false); return () => controller.abort(); }
    Promise.all([
      apiGet<{ findings: { id: string; explanation: string }[] }[]>(user, `/v1/identities/${identityId}/risk-assessments?limit=1`, controller.signal),
      apiGet<{ id: string; entitlement_id: string; decision: string }[]>(user, `/v1/identities/${identityId}/policy-evaluations?limit=200`, controller.signal)
    ]).then(([risk, policies]) => {
      if (controller.signal.aborted) return;
      setChoices([
        ...(risk[0]?.findings ?? []).map((finding) => ({ id: finding.id, kind: "risk" as const, label: finding.explanation })),
        ...policies.map((policy) => ({ id: policy.id, kind: "policy" as const, label: `Policy ${policy.decision}: entitlement ${policy.entitlement_id}` }))
      ]);
    }).catch(() => { if (!controller.signal.aborted) setError("Target evidence unavailable; no review can be opened."); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [identityId, user]);
  function accept(review: ReviewCase) {
    onReviewsChanged([review, ...reviews.filter((item) => item.id !== review.id)]);
    setSelectedId(review.id);
  }
  async function openCase() {
    const choice = choices.find((item) => item.id === choiceId);
    if (pending || !choice) return;
    setPending(true); setError("");
    try {
      accept(await apiPost<ReviewCase>(user, "/v1/reviews", {
        identity_id: identityId, finding_id: choice.kind === "risk" ? choice.id : null,
        policy_evaluation_id: choice.kind === "policy" ? choice.id : null,
        proposed_action: proposal, closure_goal: proposal === "revoke" ? goal : "record_decision"
      }));
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not open review"); }
    finally { setPending(false); }
  }
  async function register() {
    setPending(true); setError("");
    try {
      const reviewer = await apiPost<Reviewer>(user, "/v1/reviewers", { identity_id: registerId, reason: registerReason });
      setReviewers((current) => [...current.filter((item) => item.id !== reviewer.id), reviewer]);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Registration failed"); }
    finally { setPending(false); }
  }
  return <div className="page assessment-reviews">
    <section className="page-heading"><div><p className="kicker">Human review</p><h1>Review exact access evidence.</h1></div><p>A decision, operator completion, and verified outcome are separate records.</p></section>
    {error && <p role="alert" className="notice notice--error">{error}</p>}
    {isAdmin && <details className="panel"><summary>Reviewer eligibility administration</summary><p>Register an authoritative OIDC account from the loaded inventory. Registration records eligibility; the account must also have reviewer permissions when acting.</p>
      <label>Account<select value={registerId} onChange={(event) => setRegisterId(event.target.value)}><option value="">Select account</option>{identities.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.source}</option>)}</select></label>
      <label>Eligibility evidence<input value={registerReason} onChange={(event) => setRegisterReason(event.target.value)} maxLength={2000} /></label>
      <button className="button button--secondary" disabled={pending || !registerId || registerReason.trim().length < 10} onClick={() => void register()}>Register eligible reviewer</button>
      <p>Registry shows up to 200 entries.</p>{reviewers.map((item) => <div key={item.id}>{item.display_name} · {item.active ? "Eligible" : "Inactive"}<button disabled={pending || registerReason.trim().length < 10} onClick={async () => {
        setPending(true); setError("");
        try { const updated = await apiPost<Reviewer>(user, `/v1/reviewers/${item.id}/eligibility`, { active: !item.active, reason: registerReason }); setReviewers((current) => current.map((value) => value.id === updated.id ? updated : value)); }
        catch (caught) { setError(caught instanceof Error ? caught.message : "Eligibility update failed"); }
        finally { setPending(false); }
      }}>{item.active ? "Deactivate" : "Reactivate"}</button></div>)}
    </details>}
    {canOpen && <section className="panel review-create"><h2>Open an exact-target review</h2><form onSubmit={(event) => { event.preventDefault(); void openCase(); }}>
      <label>Identity<select value={identityId} onChange={(event) => { setChoiceId(""); setIdentityId(event.target.value); }} required>{identities.map((identity) => <option value={identity.id} key={identity.id}>{identity.display_name} · {identity.source}</option>)}</select></label>
      <label>Evidence target<select value={choiceId} disabled={loading} onChange={(event) => setChoiceId(event.target.value)} required><option value="">{loading ? "Loading evidence…" : "Select exact finding or policy evaluation"}</option>{choices.map((choice) => <option key={choice.id} value={choice.id}>{choice.kind}: {choice.label}</option>)}</select></label>
      <label>Proposal<select value={proposal} onChange={(event) => setProposal(event.target.value)}>{["retain", "revoke", "extend", "exception"].map((value) => <option key={value}>{value}</option>)}</select></label>
      {proposal === "revoke" && <label>Closure goal<select value={goal} onChange={(event) => setGoal(event.target.value)}><option value="assignment_removed">This source assignment removed</option><option value="no_supported_paths">No supported effective paths (coverage may be insufficient)</option></select></label>}
      <button className="button button--primary" disabled={pending || loading || !choiceId}>Open or view review</button>
    </form><p>Uses the latest risk assessment and up to 200 recorded policy evaluations. Evidence older than 24 hours requires reassessment.</p></section>}
    <div className="review-workspace"><section className="panel review-queue" aria-label="Review queue"><h2>Cases in loaded page</h2>
      {orderReviews(reviews).map((review) => <button key={review.id} className={review.id === selectedId ? "review-choice selected" : "review-choice"} onClick={() => setSelectedId(review.id)} aria-pressed={review.id === selectedId}><strong>{review.title}</strong><span>{review.owner ?? "Unassigned"} · {review.status}</span><time>Due {new Date(review.due_at).toLocaleString()}</time><small>Manual work: {manualWork(review).status.replaceAll("_", " ")}</small></button>)}
    </section>{selected ? <ReviewDetail key={selected.id} user={user} principal={principal} review={selected} reviewers={reviewers} onChanged={accept} onInspect={onInspect} /> : <p>Select a review.</p>}</div>
  </div>;
}

function ReviewDetail({ user, principal, review, reviewers, onChanged, onInspect }: {
  user: User; principal: Principal | null; review: ReviewCase; reviewers: Reviewer[];
  onChanged: (review: ReviewCase) => void; onInspect: (id: string) => void;
}) {
  const [owner, setOwner] = useState(review.owner_id ?? "");
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [packet, setPacket] = useState<unknown>(null);
  const [collection, setCollection] = useState<CollectionStatus | null>(null);
  const [collectionError, setCollectionError] = useState("");
  useEffect(() => {
    setCollection(null); setCollectionError("");
    if (review.status !== "resolved" || review.resolution !== "revoke") return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function refresh() {
      try {
        const result = await apiGet<CollectionStatus>(user, `/v1/reviews/${review.id}/collection-status`, controller.signal);
        if (controller.signal.aborted) return;
        setCollection(result); setCollectionError("");
        if (result.state === "completed") {
          const latest = await apiGet<ReviewCase>(user, `/v1/reviews/${review.id}`, controller.signal);
          if (!controller.signal.aborted && latest.revision !== review.revision) onChanged(latest);
        }
        if (["queued", "running", "retry_wait"].includes(result.state)) timer = setTimeout(() => void refresh(), 5000);
      } catch (caught) {
        if (!controller.signal.aborted) setCollectionError(caught instanceof Error ? caught.message : "Collection status unavailable");
      }
    }
    void refresh();
    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, [user, review.id, review.revision, review.status, review.resolution, onChanged]);
  const canReview = principal?.roles.some((role) => ["athena-reviewer", "athena-administrator"].includes(role));
  const assigned = reviewers.find((item) => item.id === review.owner_id);
  const canDecide = assigned?.active && assigned.subject === principal?.subject && assigned.issuer === user.profile.iss;
  async function act(action: string, body: Record<string, unknown>) {
    if (pending) return;
    setPending(true); setError(""); setPacket(null);
    try { onChanged(await apiPost<ReviewCase>(user, `/v1/reviews/${review.id}/${action}`, { ...body, revision: review.revision, reason })); setReason(""); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Review action failed"); }
    finally { setPending(false); }
  }
  const work = manualWork(review);
  return <section className="panel review-detail" aria-label="Selected review"><h2>{review.title}</h2><p>{review.status} · Revision {review.revision} · Owner {review.owner ?? "Unassigned"}</p>
    <button className="button button--secondary" onClick={() => onInspect(review.identity_id)}>Inspect identity evidence</button>
    <button className="button button--secondary" disabled={pending} onClick={async () => {
      setPending(true); setError("");
      try { onChanged(await apiGet<ReviewCase>(user, `/v1/reviews/${review.id}`)); setPacket(null); }
      catch (caught) { setError(caught instanceof Error ? caught.message : "Reload failed"); }
      finally { setPending(false); }
    }}>Reload case</button>
    {!review.target_snapshot ? <p>Legacy unbound review: history is preserved. Select fresh exact evidence above to obtain a new approval.</p> : <><p>Proposal: {review.target_snapshot.proposed_action} · Closure goal: {review.target_snapshot.closure_goal}</p><details><summary>Immutable target and evidence</summary><pre>{JSON.stringify(review.target_snapshot, null, 2)}</pre></details></>}
    {error && <p role="alert">{error}</p>}
    {collectionError && <p role="alert">Collection status unavailable: {collectionError}</p>}
    {collection && <p role={collection.state === "exhausted" ? "alert" : "status"}>Verification: {collection.state.replaceAll("_", " ")} · Attempts {collection.attempts}/{collection.max_attempts}{collection.outcome ? ` · Outcome: ${collection.outcome.replaceAll("_", " ")}` : ""}{collection.state === "retry_wait" && collection.next_retry_at ? ` · Retry after ${new Date(collection.next_retry_at).toLocaleString()}` : ""}{collection.state === "exhausted" ? ". Automatic retries stopped. Check connector health and scope approval, then request verification again." : ""}{collection.state === "queued" ? ". Waiting for the tenant's collection worker." : ""}</p>}
    {canReview && review.target_snapshot && <div className="review-form">
      <label>Registered reviewer / operator<select value={owner} onChange={(event) => setOwner(event.target.value)}><option value="">Select eligible account</option>{reviewers.filter((item) => item.active).map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.subject}</option>)}</select></label>
      <label>Reason or completion evidence<textarea value={reason} onChange={(event) => setReason(event.target.value)} maxLength={2000} /></label>
      {["open", "in_review"].includes(review.status) && <button disabled={pending || !owner || reason.trim().length < 10} onClick={() => void act("assign", { owner_id: owner })}>Assign or reassign review</button>}
      {["open", "in_review"].includes(review.status) && <button disabled={pending || reason.trim().length < 10} onClick={() => void act("cancel", { decision: review.target_snapshot?.proposed_action })}>Cancel review for fresh evidence</button>}
      {review.status === "in_review" && canDecide && <button disabled={pending || reason.trim().length < 10} onClick={() => void act("decide", { decision: review.target_snapshot?.proposed_action })}>Approve proposed decision</button>}
      {review.status === "resolved" && review.resolution === "revoke" && <><button disabled={pending || !owner || reason.trim().length < 10} onClick={() => void act("fulfillment", { operator_id: owner })}>Assign manual fulfillment (due in 7 days)</button><button disabled={pending || reason.trim().length < 10} onClick={() => void act("fulfillment", { complete: true })}>Record my operator completion</button><button disabled={pending} onClick={() => void act("verify", {})}>Request fresh verification</button><p>Completion queues read-only collection for the tenant worker and returns immediately. Status updates while this case is open. A new verification request starts a fresh retry budget; it does not change provider access. Other providers report insufficient coverage.</p></>}
      <button disabled={pending} onClick={async () => {
        setPending(true); setError("");
        try { setPacket(await apiGet(user, `/v1/reviews/${review.id}/evidence`)); }
        catch (caught) { setError(caught instanceof Error ? caught.message : "Case evidence unavailable"); }
        finally { setPending(false); }
      }}>Prepare case evidence packet</button>
    </div>}
    <p role="status">Manual work: {work.status.replaceAll("_", " ")}{work.due ? ` · Due ${new Date(work.due).toLocaleString()}` : ""}</p>
    {packet !== null && <details open><summary>Case evidence packet and digest</summary><pre>{JSON.stringify(packet, null, 2)}</pre></details>}
    <h3>Append-only case history</h3><ol className="review-history">{review.events.map((event) => <li key={event.id}><strong>{event.action} · {event.actor}</strong><time>{new Date(event.occurred_at).toLocaleString()}</time><p>{event.reason}</p><details><summary>Recorded evidence</summary><pre>{JSON.stringify(event.evidence_snapshot, null, 2)}</pre></details></li>)}</ol>
  </section>;
}
