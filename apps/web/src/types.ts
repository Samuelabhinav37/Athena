export interface Principal {
  subject: string;
  username: string;
  roles: string[];
}

export interface Identity {
  id: string;
  source: string;
  username: string;
  identity_type: string;
  display_name: string;
  email: string | null;
  department: string | null;
  job_title: string | null;
  active: boolean;
  observed_at: string;
  groups: { id: string; name: string; path: string }[];
  roles: { id: string; name: string; description: string | null }[];
}

export interface Entitlement {
  id: string;
  permission: {
    name: string;
    action: string;
    privileged: boolean;
    resource: { name: string; resource_type: string; sensitivity: string };
  };
  governance: {
    status: string;
    gaps: string[];
    business_reason: string | null;
    approved_by: string | null;
    expires_at: string | null;
  };
  provenance: {
    sequence: number;
    from_label: string;
    relationship: string;
    to_label: string;
  }[];
}

export interface RiskAssessment {
  id: string;
  evaluated_at: string;
  model_version: string;
  score: number;
  level: string;
  findings: { id: string; finding_type: string; score: number; explanation: string }[];
}

export interface AnomalyAssessment {
  id: string;
  decision_score: number;
  is_anomaly: boolean;
  explanation: Record<string, unknown>;
  run: { model_version: string; algorithm: string; trained_at: string };
}

export interface IdentityExplanation {
  identity_id: string;
  generated_at: string;
  model: string;
  evidence_digest: string;
  evidence_references: string[];
  summary: string;
  findings: string[];
  limitations: string[];
  disclaimer: string;
}

export interface AttackPath {
  nodes: { id: string; kind: string; label: string }[];
  relationships: string[];
}

export interface MachineIdentityPosture {
  identity_id: string;
  username: string;
  display_name: string;
  identity_type: string;
  source: string;
  active: boolean;
  owner: string | null;
  active_entitlements: number;
  privileged_entitlements: number;
  last_used_at: string | null;
  findings: { code: string; severity: "low" | "medium" | "high"; summary: string }[];
}

export interface ReviewCase {
  id: string;
  identity_id: string;
  title: string;
  status: string;
  owner: string | null;
  due_at: string;
  resolution: string | null;
  created_at: string;
  events: { id: string; occurred_at: string; actor: string; action: string; reason: string }[];
}

export interface Connector {
  id: string;
  connector: string;
  scope: string;
  observed_at: string;
  fingerprint: string;
  cached_endpoints: number;
}

export interface MonitoringRun {
  id: string;
  schedule_key: string;
  status: string;
  attempt_count: number;
  requested_by: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  steps: { id: string; sequence: number; name: string; status: string }[];
}

export interface Execution {
  id: string;
  case_id: string;
  source: string;
  action: string;
  status: string;
  requested_by: string;
  created_at: string;
  error: string | null;
}
