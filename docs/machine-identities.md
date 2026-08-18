# Machine and workload identity governance

Athena treats service accounts, applications, workloads, API clients, and agents as first-class
identities. The posture API reads canonical PostgreSQL evidence and produces deterministic lifecycle
findings. It does not rotate credentials, disable identities, change access, or invoke remediation.

## Posture API

`GET /v1/machine-identities` requires the Athena viewer role and supports bounded pagination with a
maximum page size of 200. Each record includes identity type, source, accountable owner when known,
active and privileged entitlement counts, latest observed use, and bounded finding summaries.

The API intentionally excludes raw source metadata, trust policies, access-key identifiers, tokens,
and credentials.

## Initial findings

| Code | Meaning |
|---|---|
| `missing_owner` | No accountable owner is recorded in normalized metadata. |
| `usage_unknown` | An active identity has no last-used evidence. |
| `stale_usage` | Latest observed use is older than 90 days. |
| `stale_credential` | An active credential is reported older than 90 days. |
| `ungoverned_access` | Active entitlements lack required approval, reason, policy, or expiry evidence. |

These findings are evidence summaries, not policy decisions. OPA remains the deterministic decision
engine, and any destructive response requires human review plus separately authorized execution.

## Current evidence limits

AWS IAM roles are normalized as service accounts. The read-only collector uses `GetRole` to reduce
recognized `Owner` or `athena:owner` tags into the accountable-owner field and records AWS-reported
last-used time and region. Raw tags and role responses are not exposed. Missing owner or usage data
remains visible rather than inferred, including when AWS does not return role-use history.

Future connectors may normalize additional platform-specific ownership and workload activity into
the same contract without exposing secret material.
