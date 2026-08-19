# Provider-neutral AI explanations

Athena can translate existing identity-governance evidence into a bounded, human-readable summary.
The model is an explanation layer only: OPA remains the deterministic decision authority, analytics
remain advisory, and a human remains responsible for destructive access decisions.

## Trust boundary

`POST /v1/identities/{identity_id}/explanation` requires the viewer role and performs no database
write. Athena builds a bounded snapshot from existing identity, entitlement, provenance, policy,
risk, and anomaly evidence, then invokes the configured `AIProvider`. Ollama remains the default
local/private adapter; Azure AI is an explicit hosted adapter.

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
- Both adapters return the same Athena-owned response schema. Provider-specific data is limited to
  `provider`, `model`, and bounded `provider_metadata` such as request and finish identifiers.

## Configuration

Install Ollama separately, make the chosen local model available, and configure Athena:

```dotenv
ATHENA_OLLAMA_URL=http://localhost:11434
ATHENA_OLLAMA_MODEL=gemma3:4b
ATHENA_OLLAMA_TIMEOUT_SECONDS=60
```

Athena does not pull models automatically. Model selection, installation, licensing, and local
resource requirements remain operator-controlled.

To select Azure AI, configure an Azure OpenAI resource endpoint and deployment:

```dotenv
ATHENA_AI_PROVIDER=azure_ai
ATHENA_AZURE_AI_ENDPOINT=https://your-resource.openai.azure.com
ATHENA_AZURE_AI_DEPLOYMENT=your-deployment
ATHENA_AZURE_AI_API_VERSION=2024-10-21
ATHENA_AZURE_AI_TIMEOUT_SECONDS=60
```

Azure AI uses `DefaultAzureCredential` and never accepts an API key in Athena configuration. The
endpoint must use HTTPS on an Azure AI hostname and must not contain credentials. Before hosted
inference, Athena redacts usernames, display names, business reasons, and human-readable provenance
endpoints. Stable evidence identifiers remain available for traceability. Authentication failures,
safety refusals that omit valid structured content, transport failures, and malformed output all
fail closed.

## Request

```http
POST /v1/identities/{identity_id}/explanation
Authorization: Bearer <viewer-or-higher-token>
```

The response contains `summary`, `findings`, `limitations`, `provider`, `provider_metadata`, `model`, `generated_at`,
`evidence_digest`, `evidence_references`, and a mandatory decision-boundary disclaimer. If Ollama is
or Azure AI is unavailable or returns invalid output, Athena returns `503 Service Unavailable` and
does not invent a fallback explanation. Athena does not silently fall back between providers.
