import type { Connector, ConnectorManifest, Execution, Identity, MonitoringRun, Principal, ReviewCase, SecurityAgent, SecurityEvent } from "./types";

export function freshness(observedAt: string | undefined, now = Date.now()): "recent" | "stale" | "unknown" {
  const timestamp = observedAt ? Date.parse(observedAt) : NaN;
  if (!Number.isFinite(timestamp) || timestamp > now) return "unknown";
  return now - timestamp > 86_400_000 ? "stale" : "recent";
}

export function reviewProgress(reviews: ReviewCase[]) {
  return {
    assigned: reviews.some((review) => Boolean(review.owner) && ["in_review", "resolved"].includes(review.status)),
    completed: reviews.some((review) => review.status === "resolved" && Boolean(review.resolution))
  };
}

export function orderReviews(reviews: ReviewCase[]): ReviewCase[] {
  return [...reviews].sort((a, b) => {
    const resolved = Number(["resolved", "cancelled"].includes(a.status)) - Number(["resolved", "cancelled"].includes(b.status));
    return resolved || Date.parse(a.due_at) - Date.parse(b.due_at) || a.id.localeCompare(b.id);
  });
}

export function manualWork(review: ReviewCase, now = Date.now()) {
  const events = [...review.events].sort((a, b) => Number(a.evidence_snapshot.revision ?? 0) - Number(b.evidence_snapshot.revision ?? 0));
  events.reverse();
  const assignment = events.find((event) => event.action === "fulfillment_assigned");
  const completion = events.find((event) => event.action === "operator_completed");
  const verification = events.find((event) => event.action === "verification_recorded");
  const requested = events.find((event) => event.action === "verification_requested");
  const revision = (event: typeof assignment) => Number(event?.evidence_snapshot.revision ?? 0);
  if (!assignment) return { status: "not_assigned", due: "" };
  const due = String(assignment.evidence_snapshot.due_at ?? "");
  if (revision(assignment) > revision(completion)) return { status: Date.parse(due) < now ? "overdue" : "pending", due };
  if (revision(requested) > Math.max(revision(verification), revision(completion))) return { status: "awaiting_verification", due };
  if (revision(verification) > revision(completion)) return { status: String(verification?.evidence_snapshot.outcome ?? "unknown"), due };
  return { status: "awaiting_verification", due };
}

type Reader = <T>(path: string) => Promise<T>;

async function optional<T>(read: Reader, path: string, label: string, fallback: T) {
  try { return { data: await read<T>(path), warning: "" }; }
  catch (error) {
    // An expired session is not an optional-service outage.
    if (typeof error === "object" && error !== null && "status" in error && error.status === 401) throw error;
    return { data: fallback, warning: `${label} unavailable. This section may be incomplete; core identity evidence remains available.` };
  }
}

export async function loadAssessment(read: Reader) {
  const principal = await read<Principal>("/v1/auth/me");
  const [identities, reviews, connectors, manifests, runs, agents, events, executions] = await Promise.all([
    read<Identity[]>("/v1/identities"),
    read<ReviewCase[]>("/v1/reviews"),
    read<Connector[]>("/v1/connectors"),
    optional<ConnectorManifest[]>(read, "/v1/connectors/capabilities", "Connector capabilities", []),
    optional<MonitoringRun[]>(read, "/v1/monitoring/runs", "Monitoring history", []),
    optional<SecurityAgent[]>(read, "/v1/security/agents", "Protection agents", []),
    optional<SecurityEvent[]>(read, "/v1/security/events", "Protection events", []),
    principal.roles.includes("athena-administrator")
      ? optional<Execution[]>(read, "/v1/executions", "Execution history", [])
      : Promise.resolve({ data: [] as Execution[], warning: "" })
  ]);
  return {
    principal, identities, reviews, connectors, manifests: manifests.data, runs: runs.data,
    agents: agents.data, events: events.data, executions: executions.data,
    warnings: [manifests, runs, agents, events, executions].map((result) => result.warning).filter(Boolean)
  };
}
