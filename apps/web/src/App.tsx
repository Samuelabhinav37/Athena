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
  RiskAssessment
} from "./types";

type Page = "overview" | "identities" | "machines" | "reviews" | "operations";
type LoadState = "idle" | "loading" | "ready" | "error";

const NAV: { id: Page; label: string; eyebrow: string }[] = [
  { id: "overview", label: "Command center", eyebrow: "01" },
  { id: "identities", label: "Identity evidence", eyebrow: "02" },
  { id: "machines", label: "Machine identities", eyebrow: "03" },
  { id: "reviews", label: "Review queue", eyebrow: "04" },
  { id: "operations", label: "System operations", eyebrow: "05" }
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

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [me, identityData, reviewData, connectorData, runData] = await Promise.all([
          apiGet<Principal>(user, "/v1/auth/me"),
          apiGet<Identity[]>(user, "/v1/identities"),
          apiGet<ReviewCase[]>(user, "/v1/reviews"),
          apiGet<Connector[]>(user, "/v1/connectors"),
          apiGet<MonitoringRun[]>(user, "/v1/monitoring/runs")
        ]);
        if (!active) return;
        setPrincipal(me); setIdentities(identityData); setReviews(reviewData);
        setConnectors(connectorData); setRuns(runData);
        if (me.roles.includes("athena-administrator")) {
          setExecutions(await apiGet<Execution[]>(user, "/v1/executions"));
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
    return () => { active = false; };
  }, [user]);

  const openReviews = reviews.filter((review) => !["closed", "resolved"].includes(review.status));
  const staleConnectors = connectors.filter((connector) => Date.now() - Date.parse(connector.observed_at) > 86_400_000);
  const latestRun = runs[0];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span><div><strong>Athena</strong><small>Evidence plane</small></div></div>
        <nav aria-label="Primary navigation">
          {NAV.map((item) => (
            <button key={item.id} className={page === item.id ? "nav-item active" : "nav-item"} onClick={() => setPage(item.id)}>
              <span>{item.eyebrow}</span>{item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="status-dot" /> Policy engine connected
          <small>Deterministic decisions only</small>
        </div>
      </aside>
      <main className="workspace">
        <header className="topbar">
          <div><p className="kicker">Athena / {NAV.find((item) => item.id === page)?.label}</p></div>
          <div className="user-menu"><div><strong>{principal?.username ?? "Authenticated user"}</strong><small>{principal?.roles.at(-1)?.replace("athena-", "") ?? "loading role"}</small></div><button className="icon-button" title="Sign out" onClick={() => void userManager.signoutRedirect()}>↗</button></div>
        </header>
        {state === "loading" && <Splash message="Loading authorization evidence…" />}
        {state === "error" && <div className="notice notice--error"><strong>Evidence unavailable.</strong> {error}</div>}
        {state === "ready" && page === "overview" && <Overview identities={identities} openReviews={openReviews} staleConnectors={staleConnectors} latestRun={latestRun} executions={executions} />}
        {state === "ready" && page === "identities" && <Identities user={user} identities={identities} />}
        {state === "ready" && page === "machines" && <MachineIdentities user={user} />}
        {state === "ready" && page === "reviews" && <Reviews reviews={reviews} identities={identities} />}
        {state === "ready" && page === "operations" && <Operations user={user} connectors={connectors} runs={runs} executions={executions} isAdmin={principal?.roles.includes("athena-administrator") ?? false} />}
      </main>
    </div>
  );
}

function Overview({ identities, openReviews, staleConnectors, latestRun, executions }: { identities: Identity[]; openReviews: ReviewCase[]; staleConnectors: Connector[]; latestRun?: MonitoringRun; executions: Execution[] }) {
  const active = identities.filter((identity) => identity.active).length;
  return <div className="page"><section className="hero"><div><p className="kicker">Authorization posture</p><h1>Evidence you can<br /><em>defend.</em></h1></div><p>One view of identity lineage, governed access, deterministic policy decisions, and human review.</p></section>
    <section className="metric-grid">
      <Metric label="Observed identities" value={String(identities.length)} detail={`${active} currently active`} accent="mint" />
      <Metric label="Open reviews" value={String(openReviews.length)} detail={openReviews.length ? "Human attention required" : "Queue is clear"} accent="amber" />
      <Metric label="Stale connectors" value={String(staleConnectors.length)} detail="Older than 24 hours" accent="coral" />
      <Metric label="Pending executions" value={String(executions.filter((item) => item.status === "pending").length)} detail="Never auto-executed" accent="blue" />
    </section>
    <section className="split-grid"><article className="panel"><PanelTitle eyebrow="Latest cycle" title="Monitoring evidence" /><div className="run-summary"><div className="run-ring"><span>{latestRun?.steps.filter((step) => step.status === "completed").length ?? 0}</span><small>steps</small></div><div>{latestRun ? <><Badge value={latestRun.status} /><h3>{latestRun.schedule_key}</h3><p>Requested by {latestRun.requested_by}</p><small>{formatDate(latestRun.completed_at)}</small></> : <Empty>No monitoring runs recorded.</Empty>}</div></div></article>
      <article className="panel"><PanelTitle eyebrow="Review pressure" title="Cases approaching decision" />{openReviews.length ? <div className="stack-list">{openReviews.slice(0, 4).map((review) => <div className="stack-row" key={review.id}><div><strong>{review.title}</strong><small>Due {formatDate(review.due_at)}</small></div><Badge value={review.status} /></div>)}</div> : <Empty>No open review cases.</Empty>}</article></section>
  </div>;
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
    let active = true; setLoading(true); setDetailError(""); setExplanation(null);
    setExplanationState("idle"); setExplanationError("");
    setGraphState("loading"); setGraphError(""); setAttackPaths([]);
    Promise.all([
      apiGet<Entitlement[]>(user, `/v1/identities/${selectedId}/entitlements`),
      apiGet<RiskAssessment[]>(user, `/v1/identities/${selectedId}/risk-assessments`),
      apiGet<AnomalyAssessment[]>(user, `/v1/identities/${selectedId}/anomaly-assessments`)
    ]).then(([grants, riskData, anomalyData]) => {
      if (active) { setEntitlements(grants); setRisks(riskData); setAnomalies(anomalyData); }
    }).catch((caught: unknown) => {
      if (active) setDetailError(caught instanceof Error ? caught.message : "Unable to load identity evidence");
    }).finally(() => { if (active) setLoading(false); });
    apiGet<AttackPath[]>(user, `/v1/attack-paths/identities/${selectedId}?max_depth=6&limit=25`)
      .then((paths) => { if (active) { setAttackPaths(paths); setGraphState("ready"); } })
      .catch((caught: unknown) => {
        if (active) {
          setGraphError(caught instanceof Error ? caught.message : "Attack-path graph unavailable");
          setGraphState("error");
        }
      });
    return () => { active = false; };
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
          <div className="explanation-card"><div className="explanation-heading"><div><p className="kicker">Local model · advisory only</p><h3>Evidence explanation</h3></div><button className="button button--secondary" onClick={() => void generateExplanation()} disabled={explanationState === "loading"}>{explanationState === "loading" ? "Generating…" : explanation ? "Regenerate" : "Generate explanation"}</button></div>{explanationError && <div className="notice notice--error">{explanationError}</div>}{explanation && <div className="explanation-body"><p>{explanation.summary}</p>{explanation.findings.length > 0 && <ul>{explanation.findings.map((finding) => <li key={finding}>{finding}</li>)}</ul>}<div className="explanation-meta"><span>Model {explanation.model}</span><span>{explanation.evidence_references.length} evidence references</span><span>Digest {explanation.evidence_digest.slice(0, 12)}…</span></div><small>{explanation.disclaimer}</small>{explanation.limitations.length > 0 && <details><summary>Limitations</summary><ul>{explanation.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></details>}</div>}</div>
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
    apiGet<MachineIdentityPosture[]>(user, "/v1/machine-identities?limit=200")
      .then((data) => {
        if (!active) return;
        setItems(data); setSelectedId(data[0]?.identity_id ?? ""); setState("ready");
      })
      .catch((caught: unknown) => {
        if (!active) return;
        setError(caught instanceof Error ? caught.message : "Machine identity posture unavailable");
        setState("error");
      });
    return () => { active = false; };
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

function Reviews({ reviews, identities }: { reviews: ReviewCase[]; identities: Identity[] }) {
  const nameFor = (id: string) => identities.find((identity) => identity.id === id)?.display_name ?? id.slice(0, 8);
  return <div className="page"><section className="page-heading"><div><p className="kicker">Human decision boundary</p><h1>Review with context.<br /><em>Act with proof.</em></h1></div><p className="heading-note">Athena records decisions as immutable evidence. Destructive access changes always remain separately authorized.</p></section>
    <section className="panel table-panel"><div className="review-table table-header"><span>Case</span><span>Identity</span><span>Owner</span><span>Due</span><span>Status</span></div>{reviews.length ? reviews.map((review) => <div className="review-table" key={review.id}><span><strong>{review.title}</strong><small>{review.id.slice(0, 8)}</small></span><span>{nameFor(review.identity_id)}</span><span>{review.owner ?? "Unassigned"}</span><span>{formatDate(review.due_at)}</span><span><Badge value={review.status} /></span></div>) : <Empty>No review cases recorded.</Empty>}</section>
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
