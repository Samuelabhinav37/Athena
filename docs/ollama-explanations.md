# Local Ollama explanations

Athena can translate existing identity-governance evidence into a bounded, human-readable summary.
The model is an explanation layer only: OPA remains the deterministic decision authority, analytics
remain advisory, and a human remains responsible for destructive access decisions.

## Trust boundary

`POST /v1/identities/{identity_id}/explanation` requires the viewer role and performs no database
write. Athena builds a bounded snapshot from existing identity, entitlement, provenance, policy,
risk, and anomaly evidence, then sends it only to a loopback Ollama HTTP endpoint.

The service enforces these controls:

- `ATHENA_OLLAMA_URL` must use plain HTTP on `localhost`, `127.0.0.1`, or `::1`; remote endpoints are
  rejected so identity evidence cannot leave the machine through this integration.
- External identity and connector strings are explicitly marked as untrusted data, angle brackets
  are escaped before prompting, and the model receives no tools.
- Evidence is bounded to 50 entitlements, 50 policy evaluations, five risk assessments, five
  anomaly results, and 100,000 serialized characters.
- The request disables streaming, sets temperature to zero, and supplies a JSON Schema.
- Pydantic validates the returned content; missing or malformed structured output fails closed.
- Responses identify the local model, evidence record references, and a SHA-256 digest of the exact
  canonical snapshot.
- Generated text is not persisted as authoritative evidence and cannot mutate policy, reviews,
  grants, entitlements, or remediation requests.

## Configuration

Install Ollama separately, make the chosen local model available, and configure Athena:

```dotenv
ATHENA_OLLAMA_URL=http://localhost:11434
ATHENA_OLLAMA_MODEL=gemma3:4b
ATHENA_OLLAMA_TIMEOUT_SECONDS=60
```

Athena does not pull models automatically. Model selection, installation, licensing, and local
resource requirements remain operator-controlled.

## Request

```http
POST /v1/identities/{identity_id}/explanation
Authorization: Bearer <viewer-or-higher-token>
```

The response contains `summary`, `findings`, `limitations`, `model`, `generated_at`,
`evidence_digest`, `evidence_references`, and a mandatory decision-boundary disclaimer. If Ollama is
unavailable or returns invalid output, Athena returns `503 Service Unavailable` and does not invent
a fallback explanation.
