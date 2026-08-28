import { useEffect, useMemo, useState } from "react";
import type { User } from "oidc-client-ts";
import { apiGet, apiPost, apiText, ApiError } from "./api";
import { completeSignin, userManager } from "./auth";
import type {
  AnomalyAssessment,
  AttackPath,
  Connector,
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
        const [me, identityData, reviewData, connectorData, runData, agentData, eventData] = await Promise.all([
          apiGet<Principal>(user, "/v1/auth/me", controller.signal),
          apiGet<Identity[]>(user, "/v1/identities", controller.signal),
          apiGet<ReviewCase[]>(user, "/v1/reviews", controller.signal),
          apiGet<Connector[]>(user, "/v1/connectors", controller.signal),
          apiGet<MonitoringRun[]>(user, "/v1/monitoring/runs", controller.signal),
          apiGet<SecurityAgent[]>(user, "/v1/security/agents", controller.signal),
          apiGet<SecurityEvent[]>(user, "/v1/security/events", controller.signal)
        ]);
        if (!active) return;
        setPrincipal(me); setIdentities(identityData); setReviews(reviewData);
        setConnectors(connectorData); setRuns(runData);
        setSecurityAgents(agentData); setSecurityEvents(eventData);
        if (me.roles.includes("athena-administrator")) {
          setExecutions(await apiGet<Execution[]>(user, "/v1/executions", controller.signal));
        }
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

  const openReviews = reviews.filter((review) => !["closed", "resolved"].includes(review.status));
  const staleConnectors = connectors.filter((connector) => Date.now() - Date.parse(connector.observed_at) > 86_400_000);
  const latestRun = runs[0];

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
        <div className="sidebar-foot"><span className="status-dot" /> Policy engine connected<small>Deterministic decisions only</small></div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <div className="topbar-title"><strong>{NAV.find((item) => item.id === page)?.label}</strong><small>Tenant-scoped authorization evidence</small></div>
          <div className="user-menu"><div><strong>{principal?.username ?? "Authenticated user"}</strong><small>{principal?.roles.at(-1)?.replace("athena-", "") ?? "loading role"}</small></div><button className="icon-button" title="Sign out" onClick={() => void userManager.signoutRedirect()}>↗</button></div>
        </header>
        {state === "loading" && <Splash message="Loading authorization evidence…" />}
        {state === "error" && <WorkspaceUnavailable error={error} />}
        {state === "ready" && page === "overview" && <Overview identities={identities} openReviews={openReviews} staleConnectors={staleConnectors} latestRun={latestRun} executions={executions} connectors={connectors} onNavigate={setPage} />}
        {state === "ready" && page === "identities" && <Identities user={user} identities={identities} />}
        {state === "ready" && page === "security" && <EmailWebSecurity agents={securityAgents} events={securityEvents} />}
        {state === "ready" && page === "machines" && <MachineIdentities user={user} />}
        {state === "ready" && page === "reviews" && <Reviews user={user} principal={principal} reviews={reviews} identities={identities} onReviewsChanged={setReviews} onExecutionCreated={(execution) => setExecutions((current) => [execution, ...current])} />}
        {state === "ready" && page === "operations" && <Operations user={user} connectors={connectors} runs={runs} executions={executions} isAdmin={principal?.roles.includes("athena-administrator") ?? false} />}
        {state === "ready" && page === "setup" && <SystemSetup connectors={connectors} latestRun={latestRun} isAdmin={principal?.roles.includes("athena-administrator") ?? false} />}
      </main>
    </div>
  );
}

function Overview({ identities, openReviews, staleConnectors, latestRun, executions, connectors, onNavigate }: { identities: Identity[]; openReviews: ReviewCase[]; staleConnectors: Connector[]; latestRun?: MonitoringRun; executions: Execution[]; connectors: Connector[]; onNavigate: (page: Page) => void }) {
  const active = identities.filter((identity) => identity.active).length;
  const pending = executions.filter((item) => item.status === "pending").length;
  const connectorNames = new Set(connectors.map((connector) => connector.connector));
  return <div className="page command-page"><section className="command-welcome"><div><p className="kicker">Authorization posture</p><h1>Good morning, analyst</h1><span>Here is what needs attention across your identity environment.</span></div><button className="button button--secondary" onClick={() => onNavigate("reviews")}>Open work queue →</button></section>
    {(identities.length === 0 || connectors.length === 0 || !latestRun) && <FirstRunGuide identities={identities} connectors={connectors} latestRun={latestRun} openReviews={openReviews} onNavigate={onNavigate} />}
    <section className="metric-grid command-metrics"><Metric label="Open investigations" value={String(openReviews.length)} detail={openReviews.length ? "Human attention required" : "Queue is clear"} accent="coral" /><Metric label="Pending executions" value={String(pending)} detail="Never auto-executed" accent="amber" /><Metric label="Observed identities" value={String(identities.length)} detail={`${active} currently active`} accent="blue" /><Metric label="Connected sources" value={String(connectorNames.size)} detail={staleConnectors.length ? `${staleConnectors.length} needs attention` : "All reporting fresh"} accent="mint" /></section>
    <section className="command-grid"><article className="panel command-queue"><header className="command-panel-head"><div><h2>Priority work queue</h2><p>Open cases sorted by due date</p></div><button onClick={() => onNavigate("reviews")}>View all →</button></header>{openReviews.length ? <div className="command-table"><div className="command-table-head"><span>Investigation</span><span>Owner</span><span>Due</span><span>Status</span></div>{openReviews.slice(0, 6).map((review) => <button key={review.id} onClick={() => onNavigate("reviews")}><span><i /> <strong>{review.title}</strong><small>{review.id.slice(0, 8)}</small></span><span>{review.owner ?? "Unassigned"}</span><span>{formatDate(review.due_at)}</span><Badge value={review.status} /></button>)}</div> : <Empty>No open review cases.</Empty>}</article>
      <aside className="panel command-posture"><header className="command-panel-head"><div><h2>Environment posture</h2><p>Live control status</p></div></header><div className="posture-score"><strong>{staleConnectors.length ? "Needs attention" : "Healthy"}</strong><small>{connectorNames.size} connected sources</small></div><div className="setup-check"><span className="status-dot" /><p><strong>Tenant isolation</strong><small>Database-enforced scope</small></p></div><div className="setup-check"><span className="status-dot" /><p><strong>Policy authority</strong><small>Deterministic OPA decisions</small></p></div><div className={staleConnectors.length ? "setup-check setup-check--warning" : "setup-check"}><span className="status-dot" /><p><strong>Connector freshness</strong><small>{staleConnectors.length ? `${staleConnectors.length} checkpoint overdue` : "All checkpoints current"}</small></p></div><button className="button button--secondary" onClick={() => onNavigate("setup")}>Open system setup</button></aside>
      <article className="panel command-cycle"><header className="command-panel-head"><div><h2>Latest monitoring cycle</h2><p>Retryable, append-only pipeline evidence</p></div><button onClick={() => onNavigate("operations")}>History →</button></header>{latestRun ? <div className="command-run"><div className="run-ring"><span>{latestRun.steps.filter((step) => step.status === "completed").length}</span><small>steps</small></div><div><Badge value={latestRun.status} /><h3>{latestRun.schedule_key}</h3><p>Requested by {latestRun.requested_by}</p><small>{formatDate(latestRun.completed_at)}</small></div></div> : <Empty>No monitoring runs recorded.</Empty>}</article>
    </section>
  </div>;
}

function WorkspaceUnavailable({ error }: { error: string }) {
  return <div className="recovery-page"><section className="recovery-card"><div className="recovery-icon">!</div><p className="kicker">Connection check</p><h1>Workspace needs attention</h1><p className="recovery-lede">The dashboard loaded, but it cannot reach Athena’s evidence API. Your account is not the problem.</p><div className="recovery-steps"><article><span>1</span><div><strong>Start required services</strong><small>Run PostgreSQL, Keycloak, and OPA through Docker Compose.</small><code>docker compose up -d postgres keycloak opa</code></div></article><article><span>2</span><div><strong>Start the Athena API</strong><small>Keep this command running in a separate PowerShell window.</small><code>.\.venv\Scripts\uvicorn.exe athena.main:app --app-dir apps/api/src</code></div></article><article><span>3</span><div><strong>Refresh this page</strong><small>Athena will automatically load your tenant-scoped evidence after the API responds.</small></div></article></div><details><summary>Technical detail</summary><p>{error}</p></details><button className="button button--primary" onClick={() => window.location.reload()}>Check connection again <span>↻</span></button></section></div>;
}

function FirstRunGuide({ identities, connectors, latestRun, openReviews, onNavigate }: { identities: Identity[]; connectors: Connector[]; latestRun?: MonitoringRun; openReviews: ReviewCase[]; onNavigate: (page: Page) => void }) {
  const steps = [
    { title: "Connect an identity source", detail: "Confirm Keycloak, GitHub, or Microsoft Azure is reporting.", done: connectors.length > 0, page: "setup" as Page },
    { title: "Collect identity evidence", detail: "Synchronize users, groups, roles, and access assignments.", done: identities.length > 0, page: "identities" as Page },
    { title: "Run the monitoring pipeline", detail: "Create policy, risk, and review evidence for analysts.", done: Boolean(latestRun), page: "operations" as Page },
    { title: "Complete your first review", detail: "Inspect evidence and record a human access decision.", done: openReviews.length > 0, page: "reviews" as Page }
  ];
  const completed = steps.filter((step) => step.done).length;
  return <section className="first-run"><header><div><p className="kicker">Getting started</p><h2>Your first Athena workflow</h2><span>Complete these steps in order. Athena will update this checklist from real evidence.</span></div><strong>{completed} / {steps.length}</strong></header><div className="first-run-progress"><span style={{ width: `${(completed / steps.length) * 100}%` }} /></div><div className="first-run-steps">{steps.map((step, index) => <button className={step.done ? "is-done" : index === completed ? "is-next" : ""} key={step.title} onClick={() => onNavigate(step.page)}><span>{step.done ? "✓" : index + 1}</span><p><strong>{step.title}</strong><small>{step.detail}</small></p><i>{step.done ? "Complete" : index === completed ? "Do this next →" : "Not started"}</i></button>)}</div></section>;
}

function Metric({ label, value, detail, accent }: { label: string; value: string; detail: string; accent: string }) {
  return <article className={`metric metric--${accent}`}><p>{label}</p><strong>{value}</strong><small>{detail}</small></article>;
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return <header className="panel-title"><p>{eyebrow}</p><h2>{title}</h2></header>;
}

function Identities({ user, identities }: { user: User; identities: Identity[] }) {
  const [selectedId, setSelectedId] = useState(identities[0]?.id ?? "");
  const [query, setQuery] = useState("");
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
  const filtered = useMemo(() => identities.filter((identity) => `${identity.display_name} ${identity.username} ${identity.department}`.toLowerCase().includes(query.toLowerCase())), [identities, query]);
  const selected = identities.find((identity) => identity.id === selectedId);

  useEffect(() => {
    if (!selectedId) return;
    const controller = new AbortController();
    let active = true; setLoading(true); setDetailError(""); setExplanation(null);
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
    setExplanationState("loading"); setExplanationError("");
    try {
      const generated = await apiPost<IdentityExplanation>(
        user,
        `/v1/identities/${selectedId}/explanation`
      );
      setExplanation(generated); setExplanationState("ready");
    } catch (caught) {
      setExplanationError(caught instanceof Error ? caught.message : "Explanation unavailable");
      setExplanationState("error");
    }
  }

  return <div className="page"><section className="page-heading"><div><p className="kicker">Identity inventory</p><h1>Trace every permission<br /><em>to its origin.</em></h1></div><input className="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search identities" aria-label="Search identities" /></section>
    <div className="identity-layout"><section className="identity-list" aria-label="Identities">{filtered.map((identity) => <button key={identity.id} className={identity.id === selectedId ? "identity-row selected" : "identity-row"} onClick={() => setSelectedId(identity.id)}><span className="avatar">{identity.display_name.slice(0, 1)}</span><span><strong>{identity.display_name}</strong><small>{identity.department ?? identity.source} · {identity.username}</small></span><span className={identity.active ? "live-dot" : "live-dot inactive"} /></button>)}</section>
      <section className="evidence-panel">{selected ? <><header className="identity-header"><div><p>{selected.source} / {selected.identity_type}</p><h2>{selected.display_name}</h2><span>{selected.job_title ?? "Title unavailable"} · {selected.email ?? "Email unavailable"}</span></div><Badge value={selected.active ? "active" : "inactive"} /></header>
        {loading ? <div className="inline-loader">Loading evidence…</div> : detailError ? <div className="notice notice--error">{detailError}</div> : <><div className="evidence-stats"><div><strong>{entitlements.length}</strong><small>Entitlements</small></div><div><strong>{risks[0]?.score.toFixed(2) ?? "—"}</strong><small>Risk score</small></div><div><strong>{anomalies.filter((item) => item.is_anomaly).length}</strong><small>Anomalies</small></div></div>
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

function Reviews({ user, principal, reviews, identities, onReviewsChanged, onExecutionCreated }: { user: User; principal: Principal | null; reviews: ReviewCase[]; identities: Identity[]; onReviewsChanged: (reviews: ReviewCase[]) => void; onExecutionCreated: (execution: Execution) => void }) {
  const [identityId, setIdentityId] = useState(identities[0]?.id ?? "");
  const [owner, setOwner] = useState("");
  const [reason, setReason] = useState("");
  const [decision, setDecision] = useState("retain");
  const [actionState, setActionState] = useState<LoadState>("idle");
  const [actionError, setActionError] = useState("");
  const nameFor = (id: string) => identities.find((identity) => identity.id === id)?.display_name ?? id.slice(0, 8);
  const roles = principal?.roles ?? [];
  const canOpen = roles.some((role) => ["athena-analyst", "athena-reviewer", "athena-administrator"].includes(role));
  const canReview = roles.some((role) => ["athena-reviewer", "athena-administrator"].includes(role));
  const isAdmin = roles.includes("athena-administrator");
  async function refresh() { onReviewsChanged(await apiGet<ReviewCase[]>(user, "/v1/reviews")); }
  async function act(operation: () => Promise<unknown>) {
    setActionState("loading"); setActionError("");
    try { await operation(); await refresh(); setReason(""); setActionState("ready"); }
    catch (caught) { setActionError(caught instanceof Error ? caught.message : "Review action failed"); setActionState("error"); }
  }
  async function requestExecution(review: ReviewCase) {
    setActionState("loading"); setActionError("");
    try {
      const execution = await apiPost<Execution>(user, "/v1/executions", { case_id: review.id, idempotency_key: `ui-${review.id}-revoke` });
      onExecutionCreated(execution); setActionState("ready");
    } catch (caught) { setActionError(caught instanceof Error ? caught.message : "Execution request failed"); setActionState("error"); }
  }
  return <div className="page"><section className="page-heading"><div><p className="kicker">Human decision boundary</p><h1>Review with context.<br /><em>Act with proof.</em></h1></div><p className="heading-note">Athena records decisions as immutable evidence. Destructive access changes always remain separately authorized.</p></section>
    {actionError && <div className="notice notice--error">{actionError}</div>}
    {canOpen && <section className="panel action-panel"><PanelTitle eyebrow="New evidence review" title="Open a case" /><div className="action-form"><select value={identityId} onChange={(event) => setIdentityId(event.target.value)}>{identities.map((identity) => <option value={identity.id} key={identity.id}>{identity.display_name}</option>)}</select><input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Optional owner" /><button className="button button--secondary" disabled={!identityId || actionState === "loading"} onClick={() => void act(() => apiPost(user, "/v1/reviews", { identity_id: identityId, owner: owner || null, due_days: 7 }))}>Open review</button></div></section>}
    <section className="panel table-panel"><div className="review-table table-header"><span>Case</span><span>Identity</span><span>Owner</span><span>Due</span><span>Status / actions</span></div>{reviews.length ? reviews.map((review) => <div className="review-table" key={review.id}><span><strong>{review.title}</strong><small>{review.id.slice(0, 8)}</small></span><span>{nameFor(review.identity_id)}</span><span>{review.owner ?? "Unassigned"}</span><span>{formatDate(review.due_at)}</span><span><Badge value={review.status} />{canReview && review.status !== "resolved" && <div className="review-actions"><input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Evidence-based reason" />{review.status === "open" && <button onClick={() => void act(() => apiPost(user, `/v1/reviews/${review.id}/assign`, { owner: owner || principal?.username, reason }))}>Assign</button>}{review.status === "in_review" && <><select value={decision} onChange={(event) => setDecision(event.target.value)}><option value="retain">Retain</option><option value="revoke">Revoke</option><option value="extend">Extend</option><option value="exception">Exception</option></select><button onClick={() => void act(() => apiPost(user, `/v1/reviews/${review.id}/decide`, { decision, reason }))}>Decide</button></>}</div>}{isAdmin && review.status === "resolved" && review.resolution === "revoke" && <button className="button button--secondary" onClick={() => void requestExecution(review)}>Request execution</button>}</span></div>) : <Empty>No review cases recorded.</Empty>}</section>
  </div>;
}

function EmailWebSecurity({ agents, events }: { agents: SecurityAgent[]; events: SecurityEvent[] }) {
  const critical = events.filter((event) => event.severity === "critical").length;
  const blocked = events.filter((event) => event.action === "blocked").length;
  const overrides = events.filter((event) => event.action === "allowed_override").length;
  const agentName = (id: string) => agents.find((agent) => agent.id === id)?.display_name ?? id.slice(0, 8);
  return <div className="page security-page"><section className="page-heading"><div><p className="kicker">Local protection evidence</p><h1>Email & web security</h1></div><p className="heading-note">Moat and Clutter act locally first, then report minimized evidence. Athena being unavailable never weakens browser protection.</p></section>
    <section className="metric-grid"><Metric label="Enrolled agents" value={String(agents.length)} detail={`${agents.filter((agent) => agent.agent_type === "moat").length} Moat · ${agents.filter((agent) => agent.agent_type === "clutter").length} Clutter`} accent="blue" /><Metric label="Blocked locally" value={String(blocked)} detail="Protection did not wait for Athena" accent="mint" /><Metric label="Critical events" value={String(critical)} detail="Highest analyst priority" accent="coral" /><Metric label="User overrides" value={String(overrides)} detail="Human justification required" accent="amber" /></section>
    <section className="split-grid security-layout"><article className="panel"><header className="command-panel-head"><div><h2>Protection activity</h2><p>Privacy-minimized, append-only agent evidence</p></div></header>{events.length ? <div className="security-table"><div className="security-row security-row--head"><span>Event</span><span>Agent</span><span>Indicator</span><span>Time</span></div>{events.map((event) => <div className="security-row" key={event.id}><span><Badge value={event.severity} /><strong>{event.action.replaceAll("_", " ")}</strong><small>{event.rule_id}</small></span><span>{agentName(event.agent_id)}</span><span>{event.target_indicator ?? "Minimized"}</span><time>{formatDate(event.occurred_at)}</time></div>)}</div> : <Empty>No browser or mailbox security evidence recorded.</Empty>}</article>
      <aside className="panel"><header className="command-panel-head"><div><h2>Enrolled protection agents</h2><p>Machine credentials are separate from human OIDC</p></div></header>{agents.length ? <div className="stack-list">{agents.map((agent) => <div className="stack-row" key={agent.id}><div><strong>{agent.display_name}</strong><small>{agent.agent_type} · {agent.external_id}</small></div><Badge value="active" /></div>)}</div> : <Empty>No agents enrolled. An administrator must provision Moat or Clutter.</Empty>}</aside>
    </section>
  </div>;
}

function SystemSetup({ connectors, latestRun, isAdmin }: { connectors: Connector[]; latestRun?: MonitoringRun; isAdmin: boolean }) {
  const latestByConnector = new Map<string, Connector>();
  connectors.forEach((connector) => {
    const current = latestByConnector.get(connector.connector);
    if (!current || Date.parse(connector.observed_at) > Date.parse(current.observed_at)) latestByConnector.set(connector.connector, connector);
  });
  const knownSources = [
    { id: "keycloak", name: "Keycloak", detail: "Users, groups, roles, and service accounts" },
    { id: "github", name: "GitHub", detail: "Organization members, teams, and repositories" },
    { id: "azure", name: "Microsoft Azure", detail: "Entra identities and Azure RBAC assignments" }
  ];
  return <div className="page setup-page"><section className="page-heading"><div><p className="kicker">Administration</p><h1>System setup</h1></div><p className="heading-note">Review data-source readiness and operating boundaries. Credentials stay outside the browser and access-changing actions require separate authorization.</p></section>
    {!isAdmin && <div className="notice setup-notice">Administrator role is required to change deployment configuration. This view remains read-only.</div>}
    <section className="setup-summary"><article><small>Configured sources</small><strong>{latestByConnector.size} / {knownSources.length}</strong><span>Reporting connector evidence</span></article><article><small>Latest monitoring run</small><strong>{latestRun?.status ?? "Not run"}</strong><span>{latestRun ? formatDate(latestRun.completed_at) : "No schedule evidence"}</span></article><article><small>Safety boundary</small><strong>Human approval</strong><span>No automatic access changes</span></article></section>
    <section className="setup-layout"><article className="panel setup-sources"><header className="command-panel-head"><div><h2>Identity and application sources</h2><p>Read-only connector status from recorded checkpoints</p></div></header>{knownSources.map((source) => { const checkpoint = latestByConnector.get(source.id); const fresh = checkpoint && Date.now() - Date.parse(checkpoint.observed_at) <= 86_400_000; return <div className="setup-source" key={source.id}><span className={fresh ? "source-icon source-icon--healthy" : "source-icon"}>{checkpoint ? "✓" : "+"}</span><div><strong>{source.name}</strong><small>{source.detail}</small></div><div className="source-status"><Badge value={checkpoint ? (fresh ? "active" : "stale") : "not_configured"} /><small>{checkpoint ? `Last evidence ${formatDate(checkpoint.observed_at)}` : "Use the deployment guide to connect"}</small></div></div>; })}</article>
      <aside className="panel setup-boundaries"><header className="command-panel-head"><div><h2>Protected boundaries</h2><p>Non-negotiable platform controls</p></div></header><div className="setup-check"><span className="status-dot" /><p><strong>Read-only collection</strong><small>Connectors cannot grant or revoke access</small></p></div><div className="setup-check"><span className="status-dot" /><p><strong>Tenant-scoped evidence</strong><small>PostgreSQL row-level isolation</small></p></div><div className="setup-check"><span className="status-dot" /><p><strong>Deterministic policy</strong><small>OPA remains the decision authority</small></p></div><div className="setup-check"><span className="status-dot" /><p><strong>Human remediation approval</strong><small>Destructive requests remain pending</small></p></div></aside>
    </section>
  </div>;
}

function Operations({ user, connectors, runs, executions, isAdmin }: { user: User; connectors: Connector[]; runs: MonitoringRun[]; executions: Execution[]; isAdmin: boolean }) {
  const [reportState, setReportState] = useState<LoadState>("idle");
  const [reportError, setReportError] = useState("");
  async function downloadReport() {
    setReportState("loading"); setReportError("");
    try {
      const markdown = await apiText(user, "/v1/reports/evidence.md");
      const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown" }));
      const link = document.createElement("a");
      link.href = url; link.download = "athena-authorization-evidence.md"; link.click();
      URL.revokeObjectURL(url); setReportState("ready");
    } catch (caught) {
      setReportError(caught instanceof Error ? caught.message : "Report unavailable");
      setReportState("error");
    }
  }
  return <div className="page"><section className="page-heading"><div><p className="kicker">Operational evidence</p><h1>Know what ran.<br /><em>Know what changed.</em></h1></div>{isAdmin && <button className="button button--secondary" disabled={reportState === "loading"} onClick={() => void downloadReport()}>{reportState === "loading" ? "Building report…" : "Download evidence report"}</button>}</section>{reportError && <div className="notice notice--error">{reportError}</div>}
    <section className="split-grid"><article className="panel"><PanelTitle eyebrow="Source freshness" title="Connector checkpoints" />{connectors.length ? <div className="stack-list">{connectors.map((item) => <div className="stack-row" key={item.id}><div><strong>{item.connector}</strong><small>{item.scope} · {item.cached_endpoints} cached endpoints</small></div><time>{formatDate(item.observed_at)}</time></div>)}</div> : <Empty>No connector checkpoints recorded.</Empty>}</article>
      <article className="panel"><PanelTitle eyebrow="Idempotent pipeline" title="Monitoring history" />{runs.length ? <div className="stack-list">{runs.slice(0, 6).map((run) => <div className="stack-row" key={run.id}><div><strong>{run.schedule_key}</strong><small>{run.steps.length} steps · attempt {run.attempt_count}</small></div><Badge value={run.status} /></div>)}</div> : <Empty>No monitoring runs recorded.</Empty>}</article></section>
    <section className="panel executions"><PanelTitle eyebrow="Administrator evidence" title="Remediation requests" />{!isAdmin ? <Empty>Administrator role required to view execution evidence.</Empty> : executions.length ? <div className="stack-list">{executions.map((item) => <div className="stack-row" key={item.id}><div><strong>{item.action} · {item.source}</strong><small>Requested by {item.requested_by} · {formatDate(item.created_at)}</small></div><Badge value={item.status} /></div>)}</div> : <Empty>No remediation requests recorded.</Empty>}</section>
  </div>;
}

export default App;
