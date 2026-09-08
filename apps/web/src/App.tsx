import { useEffect, useMemo, useRef, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet, apiPost, apiText, ApiError } from "./api";
import { completeSignin, userManager } from "./auth";
import { freshness, loadAssessment, orderReviews, reviewProgress } from "./assessment";
import { ConnectorCoverage } from "./ConnectorCoverage";
import { IdentityInventory } from "./IdentityInventory";
import { ReviewWorkspace } from "./ReviewWorkspace";
import type {
  AnomalyAssessment,
  AttackPath,
  Connector,
  ConnectorManifest,
  Entitlement,
  Execution,
  Identity,
  IdentityExplanation,
  MachineIdentityPosture,
  MonitoringRun,
  Principal,
  ReviewCase,
  RiskAssessment,
  SecurityAgent,
  SecurityEvent
} from "./types";

type Page = "overview" | "security" | "identities" | "machines" | "reviews" | "operations" | "setup";
type LoadState = "idle" | "loading" | "ready" | "error";

const NAV: { id: Page; label: string; eyebrow: string }[] = [
  { id: "overview", label: "Command center", eyebrow: "⌂" },
  { id: "reviews", label: "Investigations", eyebrow: "◇" },
  { id: "security", label: "Email & web security", eyebrow: "◈" },
  { id: "identities", label: "Identity evidence", eyebrow: "♙" },
  { id: "machines", label: "Machine identities", eyebrow: "▦" },
  { id: "operations", label: "Reports & operations", eyebrow: "▤" },
  { id: "setup", label: "System setup", eyebrow: "⚙" }
];

function formatDate(value: string | null): string {
  if (!value) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function Badge({ value }: { value: string }) {
  return <span className={`badge badge--${value.toLowerCase().replaceAll("_", "-")}`}>{value}</span>;
}

function Empty({ children }: { children: string }) {
  return <div className="empty-state">{children}</div>;
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<LoadState>("loading");
  const [authError, setAuthError] = useState("");

  useEffect(() => {
    let active = true;
    async function restoreSession() {
      try {
        const current = window.location.pathname === "/auth/callback"
          ? await completeSignin()
          : await userManager.getUser();
        if (!active) return;
        if (current && !current.expired) setUser(current);
        setAuthState("ready");
      } catch (error) {
        if (!active) return;
        setAuthError(error instanceof Error ? error.message : "Authentication failed");
        setAuthState("error");
      }
    }
    void restoreSession();
    return () => { active = false; };
  }, []);

  if (authState === "loading") return <Splash message="Restoring secure session…" />;
  if (!user) {
    return (
      <main className="signin-shell">
        <div className="signin-art" aria-hidden="true">
          <div className="orbit orbit--one" />
          <div className="orbit orbit--two" />
          <span className="monogram">A</span>
        </div>
        <section className="signin-panel">
          <p className="kicker">Continuous authorization intelligence</p>
          <h1>Every access path.<br /><em>Accounted for.</em></h1>
          <p className="lede">Athena reconstructs authorization lineage, surfaces governance drift, and preserves the evidence behind every human decision.</p>
          {authError && <div className="notice notice--error">{authError}</div>}
          <button className="button button--primary" onClick={() => void userManager.signinRedirect()}>
            Enter secure workspace <span>→</span>
          </button>
          <p className="fine-print">Authorization code flow · PKCE S256 · Keycloak</p>
        </section>
      </main>
    );
  }
  return <Dashboard user={user} />;
}

function Splash({ message }: { message: string }) {
  return <main className="splash"><span className="pulse" /><p>{message}</p></main>;
}

function Dashboard({ user }: { user: User }) {
  const [page, setPage] = useState<Page>("overview");
  const [manifests, setManifests] = useState<ConnectorManifest[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [selectedIdentityId, setSelectedIdentityId] = useState("");
  const [selectedReviewId, setSelectedReviewId] = useState("");
  const [exportPrepared, setExportPrepared] = useState(false);
  const [state, setState] = useState<LoadState>("loading");
  const [error, setError] = useState("");
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [reviews, setReviews] = useState<ReviewCase[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [runs, setRuns] = useState<MonitoringRun[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [securityAgents, setSecurityAgents] = useState<SecurityAgent[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    async function load() {
      try {
        const data = await loadAssessment(<T,>(path: string) => apiGet<T>(user, path, controller.signal));
        if (!active) return;
        setPrincipal(data.principal); setIdentities(data.identities); setReviews(data.reviews);
        setConnectors(data.connectors); setManifests(data.manifests); setRuns(data.runs);
        setSecurityAgents(data.agents); setSecurityEvents(data.events);
        setExecutions(data.executions); setWarnings(data.warnings);
        setState("ready");
      } catch (caught) {
        if (!active) return;
        if (caught instanceof ApiError && caught.status === 401) await userManager.removeUser();
        setError(caught instanceof Error ? caught.message : "Unable to load Athena evidence");
        setState("error");
      }
    }
    void load();
    return () => { active = false; controller.abort(); };
  }, [user]);

  const openReviews = orderReviews(reviews.filter((review) => ["open", "in_review"].includes(review.status)));
  const staleConnectors = connectors.filter((connector) => freshness(connector.observed_at) !== "recent");
  const latestRun = runs[0];
  async function inspectIdentity(id: string) {
    try {
      if (!identities.some((item) => item.id === id)) {
        const identity = await apiGet<Identity>(user, `/v1/identities/${id}`);
        setIdentities((current) => [...current.filter((item) => item.id !== id), identity]);
      }
      setSelectedIdentityId(id); setPage("identities");
    } catch {
      setWarnings((current) => [...new Set([...current, "Requested identity evidence could not be loaded. Check permissions and retry."])]);
    }
  }
  function startReview(identity: Identity) {
    setIdentities((current) => [...current.filter((item) => item.id !== identity.id), identity]);
    setSelectedIdentityId(identity.id);
    setSelectedReviewId(reviews.find((item) => item.identity_id === identity.id && item.status !== "resolved")?.id ?? "");
    setPage("reviews");
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span><div><strong>Athena</strong><small>Analyst center</small></div></div>
        <nav aria-label="Primary navigation">
          {NAV.map((item) => (
            <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => setPage(item.id)}>
              <span>{item.eyebrow}</span>{item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot"><span className="status-dot" /> Policy decisions are deterministic<small>Runtime health is not inferred</small></div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <div className="topbar-title"><strong>{NAV.find((item) => item.id === page)?.label}</strong><small>Tenant-scoped authorization evidence</small></div>
          <div className="user-menu"><div><strong>{principal?.username ?? "Authenticated user"}</strong><small>{principal?.roles.at(-1)?.replace("athena-", "") ?? "loading role"}</small></div><button className="icon-button" title="Sign out" onClick={() => void userManager.signoutRedirect()}>↗</button></div>
        </header>
        {state === "loading" && <Splash message="Loading authorization evidence…" />}
        {state === "error" && <WorkspaceUnavailable error={error} />}
        {state === "ready" && warnings.length > 0 && <div className="workspace-warnings" role="status">{warnings.map((warning) => <p key={warning}>{warning}</p>)}</div>}
        {state === "ready" && <p className="inventory-scope">Lists show the loaded API page, not tenant-wide totals. Empty results do not prove that access is safe or collection is complete.</p>}
        {state === "ready" && page === "overview" && <Overview identities={identities} openReviews={openReviews} staleConnectors={staleConnectors} latestRun={latestRun} executions={executions} connectors={connectors} reviews={reviews} exportPrepared={exportPrepared} onNavigate={setPage} onReview={(id) => { setSelectedReviewId(id); setPage("reviews"); }} />}
        {state === "ready" && page === "identities" && <Identities user={user} identities={identities} initialSelectedId={selectedIdentityId} manifests={manifests} connectors={connectors} onReview={startReview} />}
        {state === "ready" && page === "security" && <EmailWebSecurity agents={securityAgents} events={securityEvents} />}
        {state === "ready" && page === "machines" && <MachineIdentities user={user} />}
        {state === "ready" && page === "reviews" && <ReviewWorkspace initialIdentityId={selectedIdentityId} initialReviewId={selectedReviewId} onInspect={(id) => void inspectIdentity(id)} onExport={() => setPage("operations")} user={user} principal={principal} reviews={reviews} identities={identities} onReviewsChanged={setReviews} onExecutionCreated={(execution) => setExecutions((current) => [execution, ...current.filter((item) => item.id !== execution.id)])} />}
        {state === "ready" && page === "operations" && <Operations onExportPrepared={() => setExportPrepared(true)} user={user} connectors={connectors} runs={runs} executions={executions} isAdmin={principal?.roles.includes("athena-administrator") ?? false} />}
        {state === "ready" && page === "setup" && <SystemSetup manifests={manifests} identities={identities} connectors={connectors} latestRun={latestRun} isAdmin={principal?.roles.includes("athena-administrator") ?? false} />}
      </main>
    </div>
  );
}

function Overview({ identities, openReviews, staleConnectors, latestRun, executions, connectors, reviews, exportPrepared, onNavigate, onReview }: { reviews: ReviewCase[]; exportPrepared: boolean; onReview: (id: string) => void; identities: Identity[]; openReviews: ReviewCase[]; staleConnectors: Connector[]; latestRun?: MonitoringRun; executions: Execution[]; connectors: Connector[]; onNavigate: (page: Page) => void }) {
  const active = identities.filter((identity) => identity.active).length;
  const pending = executions.filter((item) => item.status === "pending").length;
  const connectorNames = new Set(connectors.map((connector) => connector.connector));
  return <div className="page command-page"><section className="command-welcome"><div><p className="kicker">Authorization posture</p><h1>Good morning, analyst</h1><span>Here is what needs attention across your identity environment.</span></div><button className="button button--secondary" onClick={() => onNavigate("reviews")}>Open work queue →</button></section>
    <FirstRunGuide identities={identities} connectors={connectors} reviews={reviews} exportPrepared={exportPrepared} onNavigate={onNavigate} />
    <section className="metric-grid command-metrics"><Metric label="Open investigations" value={String(openReviews.length)} detail={openReviews.length ? "Human attention required" : "No open cases in loaded page"} accent="coral" /><Metric label="Pending executions" value={String(pending)} detail="Never auto-executed" accent="amber" /><Metric label="Observed identities" value={String(identities.length)} detail={`${active} currently active`} accent="blue" /><Metric label="Connected sources" value={String(connectorNames.size)} detail={staleConnectors.length ? `${staleConnectors.length} needs attention` : (connectors.length ? "Recorded checkpoints recent" : "No checkpoint evidence")} accent="mint" /></section>
    <section className="command-grid"><article className="panel command-queue"><header className="command-panel-head"><div><h2>Priority work queue</h2><p>Open cases sorted by due date</p></div><button onClick={() => onNavigate("reviews")}>View all →</button></header>{openReviews.length ? <div className="command-table"><div className="command-table-head"><span>Investigation</span><span>Owner</span><span>Due</span><span>Status</span></div>{openReviews.slice(0, 6).map((review) => <button key={review.id} onClick={() => onReview(review.id)}><span><i /> <strong>{review.title}</strong><small>{review.id.slice(0, 8)}</small></span><span>{review.owner ?? "Unassigned"}</span><span>{formatDate(review.due_at)}</span><Badge value={review.status} /></button>)}</div> : <Empty>No open review cases.</Empty>}</article>
      <aside className="panel command-posture"><header className="command-panel-head"><div><h2>Environment posture</h2><p>Recorded evidence status</p></div></header><div className="posture-score"><strong>{staleConnectors.length ? "Needs attention" : connectors.length ? "Recent checkpoints" : "Coverage unknown"}</strong><small>{connectorNames.size} connected sources</small></div><div className="setup-check"><span className="status-dot" /><p><strong>Tenant isolation</strong><small>Database-enforced scope</small></p></div><div className="setup-check"><span className="status-dot" /><p><strong>Policy authority</strong><small>Deterministic OPA decisions</small></p></div><div className={staleConnectors.length ? "setup-check setup-check--warning" : "setup-check"}><span className="status-dot" /><p><strong>Connector freshness</strong><small>{staleConnectors.length ? `${staleConnectors.length} checkpoint overdue` : (connectors.length ? "Recorded checkpoints within 24 hours" : "No checkpoints available")}</small></p></div><button className="button button--secondary" onClick={() => onNavigate("setup")}>Open system setup</button></aside>
      <article className="panel command-cycle"><header className="command-panel-head"><div><h2>Latest monitoring cycle</h2><p>Retryable, append-only pipeline evidence</p></div><button onClick={() => onNavigate("operations")}>History →</button></header>{latestRun ? <div className="command-run"><div className="run-ring"><span>{latestRun.steps.filter((step) => step.status === "completed").length}</span><small>steps</small></div><div><Badge value={latestRun.status} /><h3>{latestRun.schedule_key}</h3><p>Requested by {latestRun.requested_by}</p><small>{formatDate(latestRun.completed_at)}</small></div></div> : <Empty>No monitoring runs recorded.</Empty>}</article>
    </section>
  </div>;
}

function chromeStoreUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "chromewebstore.google.com"
      ? url.toString()
      : undefined;
  } catch {
    return undefined;
  }
}

function WorkspaceUnavailable({ error }: { error: string }) {
  return <div className="recovery-page"><section className="recovery-card"><div className="recovery-icon">!</div><p className="kicker">Connection check</p><h1>Workspace needs attention</h1><p className="recovery-lede">The dashboard could not load required evidence. Check service availability and your account permissions, then retry.</p><div className="recovery-steps"><article><span>1</span><div><strong>Start required services</strong><small>Run PostgreSQL, Keycloak, and OPA through Docker Compose.</small><code>docker compose up -d postgres keycloak opa</code></div></article><article><span>2</span><div><strong>Start the Athena API</strong><small>Keep this command running in a separate PowerShell window.</small><code>.\.venv\Scripts\uvicorn.exe athena.main:app --app-dir apps/api/src</code></div></article><article><span>3</span><div><strong>Refresh this page</strong><small>Athena will automatically load your tenant-scoped evidence after the API responds.</small></div></article></div><details><summary>Technical detail</summary><p>{error}</p></details><button className="button button--primary" onClick={() => window.location.reload()}>Check connection again <span>↻</span></button></section></div>;
}

function FirstRunGuide({ identities, connectors, reviews, exportPrepared, onNavigate }: { identities: Identity[]; connectors: Connector[]; reviews: ReviewCase[]; exportPrepared: boolean; onNavigate: (page: Page) => void }) {
  const progress = reviewProgress(reviews);
  const steps = [
    { title: "Receive source evidence", detail: "Check source scope, observation time, and coverage limitations.", done: connectors.length > 0 || identities.length > 0, page: "setup" as Page },
    { title: "Assign an evidence review", detail: "Inspect an identity, open a case, and assign its owner.", done: progress.assigned, page: "reviews" as Page },
    { title: "Record a review decision", detail: "An open case is not a completed review.", done: progress.completed, page: "reviews" as Page },
    { title: "Prepare an evidence export", detail: "Administrator export; progress is recorded for this session only.", done: exportPrepared, page: "operations" as Page }
  ];
  const completed = steps.filter((step) => step.done).length;
  const nextIndex = steps.findIndex((step) => !step.done);
  return <section className="first-run"><header><div><p className="kicker">Getting started</p><h2>Your first Athena workflow</h2><span>Progress from loaded evidence. A review decision does not prove an upstream access change.</span></div><strong>{completed} / {steps.length}</strong></header><div className="first-run-progress"><span style={{ width: `${(completed / steps.length) * 100}%` }} /></div><div className="first-run-steps">{steps.map((step, index) => <button className={step.done ? "is-done" : index === nextIndex ? "is-next" : ""} key={step.title} onClick={() => onNavigate(step.page)}><span>{step.done ? "✓" : index + 1}</span><p><strong>{step.title}</strong><small>{step.detail}</small></p><i>{step.done ? "Recorded" : index === nextIndex ? "Do this next →" : "Not recorded"}</i></button>)}</div></section>;
}

function Metric({ label, value, detail, accent }: { label: string; value: string; detail: string; accent: string }) {
  return <article className={`metric metric--${accent}`}><p>{label}</p><strong>{value}</strong><small>{detail}</small></article>;
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return <header className="panel-title"><p>{eyebrow}</p><h2>{title}</h2></header>;
}

function Identities({ user, identities, initialSelectedId, manifests, connectors, onReview }: { user: User; identities: Identity[]; initialSelectedId: string; manifests: ConnectorManifest[]; connectors: Connector[]; onReview: (identity: Identity) => void }) {
  const [selected, setSelected] = useState<Identity | undefined>(() => identities.find((item) => item.id === initialSelectedId) ?? identities[0]);
  const selectedId = selected?.id ?? "";
  const selectionVersion = useRef(0);
  const [entitlements, setEntitlements] = useState<Entitlement[]>([]);
  const [risks, setRisks] = useState<RiskAssessment[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyAssessment[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [graphState, setGraphState] = useState<LoadState>("idle");
  const [graphError, setGraphError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [explanation, setExplanation] = useState<IdentityExplanation | null>(null);
  const [explanationState, setExplanationState] = useState<LoadState>("idle");
  const [explanationError, setExplanationError] = useState("");
  function selectIdentity(identity: Identity) {
    if (identity.id !== selectedId) {
      selectionVersion.current += 1;
      setLoading(true); setExplanation(null); setDetailError("");
    }
    setSelected(identity);
  }

  useEffect(() => () => { selectionVersion.current += 1; }, []);

  useEffect(() => {
    if (!selectedId) return;
    const controller = new AbortController();
    let active = true; setLoading(true); setDetailError(""); setExplanation(null);
    setEntitlements([]); setRisks([]); setAnomalies([]);
    setExplanationState("idle"); setExplanationError("");
    setGraphState("loading"); setGraphError(""); setAttackPaths([]);
    Promise.all([
      apiGet<Entitlement[]>(user, `/v1/identities/${selectedId}/entitlements`, controller.signal),
      apiGet<RiskAssessment[]>(user, `/v1/identities/${selectedId}/risk-assessments`, controller.signal),
      apiGet<AnomalyAssessment[]>(user, `/v1/identities/${selectedId}/anomaly-assessments`, controller.signal)
    ]).then(([grants, riskData, anomalyData]) => {
      if (active) { setEntitlements(grants); setRisks(riskData); setAnomalies(anomalyData); }
    }).catch((caught: unknown) => {
      if (active) setDetailError(caught instanceof Error ? caught.message : "Unable to load identity evidence");
    }).finally(() => { if (active) setLoading(false); });
    apiGet<AttackPath[]>(user, `/v1/attack-paths/identities/${selectedId}?max_depth=6&limit=25`, controller.signal)
      .then((paths) => { if (active) { setAttackPaths(paths); setGraphState("ready"); } })
      .catch((caught: unknown) => {
        if (active) {
          setGraphError(caught instanceof Error ? caught.message : "Attack-path graph unavailable");
          setGraphState("error");
        }
      });
    return () => { active = false; controller.abort(); };
  }, [selectedId, user]);

  async function generateExplanation() {
    if (!selectedId || explanationState === "loading") return;
    const version = selectionVersion.current;
    setExplanationState("loading"); setExplanationError("");
    try {
      const generated = await apiPost<IdentityExplanation>(
        user,
        `/v1/identities/${selectedId}/explanation`
      );
      if (version !== selectionVersion.current) return;
      setExplanation(generated); setExplanationState("ready");
    } catch (caught) {
      if (version !== selectionVersion.current) return;
      setExplanationError(caught instanceof Error ? caught.message : "Explanation unavailable");
      setExplanationState("error");
    }
  }

  return <div className="page"><section className="page-heading"><div><p className="kicker">Identity inventory</p><h1>Trace every permission<br /><em>to its origin.</em></h1></div></section>
    <div className="identity-layout"><IdentityInventory user={user} selectedId={selectedId} onSelect={selectIdentity} />
      <section className="evidence-panel">{selected ? <><header className="identity-header"><div><p>{selected.source} / {selected.identity_type}</p><h2>{selected.display_name}</h2><span>{selected.job_title ?? "Title unavailable"} · {selected.email ?? "Email unavailable"}</span></div><Badge value={selected.active ? "active" : "inactive"} /></header>
        <p className="identity-observation">Identity observed {formatDate(selected.observed_at)} · {freshness(selected.observed_at)}. An active account does not prove that every permission is currently usable.</p>
        <ConnectorCoverage source={selected.source} manifests={manifests} checkpoints={connectors} identities={[selected]} />
        {loading ? <div className="inline-loader">Loading evidence…</div> : detailError ? <div className="notice notice--error">{detailError}</div> : <><div className="evidence-stats"><div><strong>{entitlements.length}</strong><small>Entitlements</small></div><div><strong>{risks[0]?.score.toFixed(2) ?? "—"}</strong><small>Risk score</small></div><div><strong>{anomalies.filter((item) => item.is_anomaly).length}</strong><small>Anomalies</small></div></div>
          <section className="assessment-findings"><h3>Recorded findings</h3><p>Risk and anomaly findings are advisory evidence for human review.</p>
            {risks[0] && <p>Latest risk assessment: {formatDate(risks[0].evaluated_at)} · {risks[0].level} · Model {risks[0].model_version}</p>}
            {risks[0]?.findings.map((finding) => <article key={finding.id}><strong>{finding.finding_type.replaceAll("_", " ")}</strong><p>{finding.explanation}</p></article>)}
            {!risks.length && !anomalies.length ? <p>No risk or anomaly assessment is recorded. An administrator must run assessment before a review can be opened.</p> : <button className="button button--primary" onClick={() => onReview(selected)}>Review this identity</button>}
          </section>
          <div className="explanation-card"><div className="explanation-heading"><div><p className="kicker">AI explanation · advisory only</p><h3>Evidence explanation</h3></div><button className="button button--secondary" onClick={() => void generateExplanation()} disabled={explanationState === "loading"}>{explanationState === "loading" ? "Generating…" : explanation ? "Regenerate" : "Generate explanation"}</button></div>{explanationError && <div className="notice notice--error">{explanationError}</div>}{explanation && <div className="explanation-body"><p>{explanation.summary}</p>{explanation.findings.length > 0 && <ul>{explanation.findings.map((finding) => <li key={finding}>{finding}</li>)}</ul>}<div className="explanation-meta"><span>Provider {explanation.provider === "azure_ai" ? "Azure AI" : "Ollama"}</span><span>Model {explanation.model}</span><span>{explanation.evidence_references.length} evidence references</span><span>Digest {explanation.evidence_digest.slice(0, 12)}…</span></div><small>{explanation.disclaimer}</small>{explanation.limitations.length > 0 && <details><summary>Limitations</summary><ul>{explanation.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></details>}</div>}</div>
          <div className="attack-card"><div className="attack-heading"><div><p className="kicker">Neo4j · derived index</p><h3>Privileged attack paths</h3></div><span>Advisory only</span></div>{graphState === "loading" && <div className="inline-loader">Querying bounded graph paths…</div>}{graphState === "error" && <div className="graph-unavailable"><strong>Graph unavailable</strong><small>{graphError}. PostgreSQL evidence remains available.</small></div>}{graphState === "ready" && (attackPaths.length ? <div className="attack-paths">{attackPaths.map((path, pathIndex) => <div className="attack-path" key={`${selectedId}-${pathIndex}`}>{path.nodes.map((node, nodeIndex) => <div className="attack-step" key={`${node.id}-${nodeIndex}`}><div className={`attack-node attack-node--${node.kind}`}><small>{node.kind}</small><strong>{node.label}</strong></div>{nodeIndex < path.relationships.length && <span className="attack-edge">{path.relationships[nodeIndex]} →</span>}</div>)}</div>)}</div> : <Empty>No privileged resource paths found within six hops.</Empty>)}</div>
          <div className="evidence-section"><h3>Authorization lineage</h3>{entitlements.length ? entitlements.map((item) => <article className="entitlement" key={item.id}><div className="entitlement-head"><div><strong>{item.permission.name}</strong><small>{item.permission.action} on {item.permission.resource.name}</small></div><Badge value={item.governance.status} /></div>{item.provenance.map((edge) => <div className="lineage" key={`${item.id}-${edge.sequence}`}><span>{edge.from_label}</span><i>{edge.relationship} →</i><span>{edge.to_label}</span></div>)}{item.governance.gaps.length > 0 && <p className="gap">Governance gaps: {item.governance.gaps.join(", ")}</p>}</article>) : <Empty>No entitlements materialized for this identity.</Empty>}</div></>}</> : <Empty>Select an identity to inspect evidence.</Empty>}</section></div>
  </div>;
}

function MachineIdentities({ user }: { user: User }) {
  const [items, setItems] = useState<MachineIdentityPosture[]>([]);
  const [state, setState] = useState<LoadState>("loading");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [findingFilter, setFindingFilter] = useState("all");
  const [selectedId, setSelectedId] = useState("");

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    apiGet<MachineIdentityPosture[]>(user, "/v1/machine-identities?limit=200", controller.signal)
      .then((data) => {
        if (!active) return;
        setItems(data); setSelectedId(data[0]?.identity_id ?? ""); setState("ready");
      })
      .catch((caught: unknown) => {
        if (!active) return;
        setError(caught instanceof Error ? caught.message : "Machine identity posture unavailable");
        setState("error");
      });
    return () => { active = false; controller.abort(); };
  }, [user]);

  const types = useMemo(() => [...new Set(items.map((item) => item.identity_type))].sort(), [items]);
  const filtered = useMemo(() => items.filter((item) => {
    const matchesQuery = `${item.display_name} ${item.username} ${item.source} ${item.owner ?? ""}`
      .toLowerCase().includes(query.toLowerCase());
    const matchesType = typeFilter === "all" || item.identity_type === typeFilter;
    const matchesFinding = findingFilter === "all"
      || (findingFilter === "clear" ? item.findings.length === 0 : item.findings.some((finding) => finding.severity === findingFilter));
    return matchesQuery && matchesType && matchesFinding;
  }), [items, query, typeFilter, findingFilter]);
  const selected = items.find((item) => item.identity_id === selectedId);
  const highRisk = items.filter((item) => item.findings.some((finding) => finding.severity === "high")).length;
  const missingOwners = items.filter((item) => !item.owner).length;
  const privileged = items.filter((item) => item.privileged_entitlements > 0).length;

  return <div className="page machine-page"><section className="console-heading"><div><p className="kicker">Non-human access inventory</p><h1>Machine identity<br /><em>posture.</em></h1><p>Find ownership gaps, stale credentials, unknown use, and privileged access without exposing secret material.</p></div><div className="console-scope"><small>Evidence scope</small><strong>All connected sources</strong><span><i /> Read-only analysis</span></div></section>
    {state === "loading" && <Splash message="Loading machine identity posture…" />}
    {state === "error" && <div className="notice notice--error"><strong>Posture unavailable.</strong> {error}</div>}
    {state === "ready" && <><section className="console-metrics"><Metric label="Machine identities" value={String(items.length)} detail={`${items.filter((item) => item.active).length} active`} accent="blue" /><Metric label="High findings" value={String(highRisk)} detail="Prioritize investigation" accent="coral" /><Metric label="Missing owners" value={String(missingOwners)} detail="Accountability required" accent="amber" /><Metric label="Privileged" value={String(privileged)} detail="Advisory evidence only" accent="mint" /></section>
      <section className="console-panel"><header className="console-toolbar"><div><h2>Machine identities</h2><small>{filtered.length} of {items.length} resources</small></div><div className="console-filters"><input className="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find identity" aria-label="Find machine identity" /><select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} aria-label="Filter by identity type"><option value="all">All identity types</option>{types.map((type) => <option key={type} value={type}>{type.replaceAll("_", " ")}</option>)}</select><select value={findingFilter} onChange={(event) => setFindingFilter(event.target.value)} aria-label="Filter by finding severity"><option value="all">All findings</option><option value="high">High severity</option><option value="medium">Medium severity</option><option value="clear">No findings</option></select></div></header>
        <div className="machine-console"><div className="machine-table" role="table" aria-label="Machine identity posture"><div className="machine-row machine-row--head" role="row"><span>Name</span><span>Type</span><span>Owner</span><span>Access</span><span>Findings</span></div>{filtered.length ? filtered.map((item) => <button role="row" key={item.identity_id} className={item.identity_id === selectedId ? "machine-row selected" : "machine-row"} onClick={() => setSelectedId(item.identity_id)}><span><strong>{item.display_name}</strong><small>{item.source} · {item.username}</small></span><span><Badge value={item.identity_type} /></span><span>{item.owner ?? <em>Not assigned</em>}</span><span><strong>{item.active_entitlements}</strong><small>{item.privileged_entitlements} privileged</small></span><span><strong className={item.findings.some((finding) => finding.severity === "high") ? "finding-count finding-count--high" : "finding-count"}>{item.findings.length}</strong></span></button>) : <Empty>No machine identities match these filters.</Empty>}</div>
          <aside className="machine-detail">{selected ? <><header><div className="machine-symbol">{selected.display_name.slice(0, 2).toUpperCase()}</div><div><p>{selected.identity_type.replaceAll("_", " ")}</p><h2>{selected.display_name}</h2><small>{selected.source} / {selected.username}</small></div></header><div className="detail-grid"><div><small>Owner</small><strong>{selected.owner ?? "Not assigned"}</strong></div><div><small>Status</small><Badge value={selected.active ? "active" : "inactive"} /></div><div><small>Last used</small><strong>{formatDate(selected.last_used_at)}</strong></div><div><small>Privileged access</small><strong>{selected.privileged_entitlements}</strong></div></div><section className="finding-list"><div><p className="kicker">Deterministic posture</p><h3>Findings</h3></div>{selected.findings.length ? selected.findings.map((finding) => <article key={finding.code} className={`finding finding--${finding.severity}`}><div><Badge value={finding.severity} /><strong>{finding.code.replaceAll("_", " ")}</strong></div><p>{finding.summary}</p></article>) : <Empty>No lifecycle findings detected.</Empty>}</section><footer>Evidence summary only · no automatic access changes</footer></> : <Empty>Select a machine identity to inspect posture.</Empty>}</aside></div>
      </section></>}
  </div>;
}

function EmailWebSecurity({ agents, events }: { agents: SecurityAgent[]; events: SecurityEvent[] }) {
  const critical = events.filter((event) => event.severity === "critical").length;
  const blocked = events.filter((event) => event.action === "blocked").length;
  const overrides = events.filter((event) => event.action === "allowed_override").length;
  const agentName = (id: string) => agents.find((agent) => agent.id === id)?.display_name ?? id.slice(0, 8);
  const addOns = [
    { type: "moat" as const, name: "Moat", title: "Web protection", description: "Blocks phishing, malware, scams, and dangerous sites locally before they load.", storeUrl: chromeStoreUrl(import.meta.env.VITE_MOAT_STORE_URL) },
    { type: "clutter" as const, name: "Clutter", title: "Email protection", description: "Adds mailbox protection and reporting without automatically deleting suspicious email.", storeUrl: chromeStoreUrl(import.meta.env.VITE_CLUTTER_STORE_URL) }
  ];
  return <div className="page security-page"><section className="page-heading"><div><p className="kicker">Local protection evidence</p><h1>Email & web security</h1></div><p className="heading-note">Moat and Clutter act locally first, then report minimized evidence. Athena being unavailable never weakens browser protection.</p></section>
    <section className="add-on-grid">{addOns.map((addOn) => { const enrolled = agents.some((agent) => agent.agent_type === addOn.type); return <article className="panel add-on-card" key={addOn.type}><header><span className="add-on-icon">{addOn.type === "moat" ? "M" : "C"}</span><div><small>{addOn.title}</small><h2>{addOn.name}</h2></div><Badge value={enrolled ? "enrolled" : addOn.storeUrl ? "available" : "coming_soon"} /></header><p>{addOn.description}</p><ul><li>Optional installation</li><li>Local protection continues offline</li><li>Only minimized security evidence reaches Athena</li></ul>{enrolled ? <button className="button button--secondary" disabled>Agent enrolled in Athena</button> : addOn.storeUrl ? <a className="button button--primary add-on-install" href={addOn.storeUrl} target="_blank" rel="noreferrer">Add {addOn.name} protection →</a> : <button className="button button--secondary" disabled>Store listing coming soon</button>}</article>; })}</section>
    <section className="metric-grid"><Metric label="Enrolled agents" value={String(agents.length)} detail={`${agents.filter((agent) => agent.agent_type === "moat").length} Moat · ${agents.filter((agent) => agent.agent_type === "clutter").length} Clutter`} accent="blue" /><Metric label="Blocked locally" value={String(blocked)} detail="Protection did not wait for Athena" accent="mint" /><Metric label="Critical events" value={String(critical)} detail="Highest analyst priority" accent="coral" /><Metric label="User overrides" value={String(overrides)} detail="Human justification required" accent="amber" /></section>
    <section className="split-grid security-layout"><article className="panel"><header className="command-panel-head"><div><h2>Protection activity</h2><p>Privacy-minimized, append-only agent evidence</p></div></header>{events.length ? <div className="security-table"><div className="security-row security-row--head"><span>Event</span><span>Agent</span><span>Indicator</span><span>Time</span></div>{events.map((event) => <div className="security-row" key={event.id}><span><Badge value={event.severity} /><strong>{event.action.replaceAll("_", " ")}</strong><small>{event.rule_id}</small></span><span>{agentName(event.agent_id)}</span><span>{event.target_indicator ?? "Minimized"}</span><time>{formatDate(event.occurred_at)}</time></div>)}</div> : <Empty>No browser or mailbox security evidence recorded.</Empty>}</article>
      <aside className="panel"><header className="command-panel-head"><div><h2>Enrolled protection agents</h2><p>Machine credentials are separate from human OIDC</p></div></header>{agents.length ? <div className="stack-list">{agents.map((agent) => <div className="stack-row" key={agent.id}><div><strong>{agent.display_name}</strong><small>{agent.agent_type} · {agent.external_id}</small></div><Badge value="active" /></div>)}</div> : <Empty>No agents enrolled. An administrator must provision Moat or Clutter.</Empty>}</aside>
    </section>
  </div>;
}

function SystemSetup({ connectors, manifests, identities, latestRun, isAdmin }: { connectors: Connector[]; manifests: ConnectorManifest[]; identities: Identity[]; latestRun?: MonitoringRun; isAdmin: boolean }) {
  return <div className="page setup-page"><section className="page-heading"><div><p className="kicker">Read-only assessment</p><h1>Source coverage and setup</h1></div><p className="heading-note">Capability declarations describe adapter support. Checkpoints describe observations. Neither proves complete access coverage.</p></section>
    <section className="panel setup-instructions"><h2>Connect a source safely</h2><ol><li>Ask an administrator to configure the existing GitHub, Azure, or Keycloak collector in the deployment.</li><li>Have the tenant’s provider scope reviewed and approved before collection.</li><li>Run read-only synchronization and assessment, then refresh this workspace.</li><li>Inspect the source limitations and identity findings before opening a review.</li></ol><p>{isAdmin ? "Keep credentials in deployment secret configuration; never paste them into review reasons or evidence." : "Your current role can inspect evidence. An administrator manages source configuration."}</p><p>Latest monitoring status: {latestRun?.status ?? "No monitoring evidence loaded"}. Collection configuration cannot be determined from missing checkpoints.</p></section>
    <ConnectorCoverage manifests={manifests} checkpoints={connectors} identities={identities} />
  </div>;
}

function Operations({ user, connectors, runs, executions, isAdmin, onExportPrepared }: { onExportPrepared: () => void; user: User; connectors: Connector[]; runs: MonitoringRun[]; executions: Execution[]; isAdmin: boolean }) {
  const [reportState, setReportState] = useState<LoadState>("idle");
  const [reportError, setReportError] = useState("");
  const [reportFormat, setReportFormat] = useState<"md" | "json">("md");
  async function downloadReport() {
    setReportState("loading"); setReportError("");
    try {
      const report = await apiText(user, reportFormat === "md" ? "/v1/reports/evidence.md" : "/v1/reports/evidence");
      const url = URL.createObjectURL(new Blob([report], { type: reportFormat === "md" ? "text/markdown" : "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = `athena-authorization-evidence.${reportFormat}`; document.body.appendChild(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000); setReportState("ready"); onExportPrepared();
    } catch (caught) {
      setReportError(caught instanceof Error ? caught.message : "Report unavailable");
      setReportState("error");
    }
  }
  return <div className="page"><section className="page-heading"><div><p className="kicker">Operational evidence</p><h1>Know what ran.<br /><em>Know what changed.</em></h1></div>{isAdmin && <label>Evidence format<select value={reportFormat} onChange={(event) => setReportFormat(event.target.value as "md" | "json")} disabled={reportState === "loading"}><option value="md">Markdown</option><option value="json">JSON</option></select></label>}{isAdmin && <button className="button button--secondary" disabled={reportState === "loading"} onClick={() => void downloadReport()}>{reportState === "loading" ? "Building report…" : "Export tenant evidence"}</button>}</section>{reportError && <div className="notice notice--error">{reportError}</div>}
    <p>Exports contain tenant-wide evidence and review history, not only the selected case. The server verifies the evidence digest before rendering Markdown.</p>
    {!isAdmin && <p role="status">An administrator must export the tenant evidence packet. Your review remains available in Investigations.</p>}
    {reportState === "ready" && <p role="status">Evidence export prepared. Check your browser downloads. This does not verify that an access change was executed.</p>}
    <section className="split-grid"><article className="panel"><PanelTitle eyebrow="Source freshness" title="Connector checkpoints" />{connectors.length ? <div className="stack-list">{connectors.map((item) => <div className="stack-row" key={item.id}><div><strong>{item.connector}</strong><small>{item.scope} · {item.cached_endpoints} cached endpoints</small></div><time>{formatDate(item.observed_at)}</time></div>)}</div> : <Empty>No connector checkpoints recorded.</Empty>}</article>
      <article className="panel"><PanelTitle eyebrow="Idempotent pipeline" title="Monitoring history" />{runs.length ? <div className="stack-list">{runs.slice(0, 6).map((run) => <div className="stack-row" key={run.id}><div><strong>{run.schedule_key}</strong><small>{run.steps.length} steps · attempt {run.attempt_count}</small></div><Badge value={run.status} /></div>)}</div> : <Empty>No monitoring runs recorded.</Empty>}</article></section>
    <section className="panel executions"><PanelTitle eyebrow="Administrator evidence" title="Remediation requests" />{!isAdmin ? <Empty>Administrator role required to view execution evidence.</Empty> : executions.length ? <div className="stack-list">{executions.map((item) => <div className="stack-row" key={item.id}><div><strong>{item.action} · {item.source}</strong><small>Requested by {item.requested_by} · {formatDate(item.created_at)}</small></div><Badge value={item.status} /></div>)}</div> : <Empty>No remediation requests recorded.</Empty>}</section>
  </div>;
}

export default App;
