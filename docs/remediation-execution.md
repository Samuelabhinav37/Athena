# Authorized remediation execution

Athena separates human decisions, execution authorization, connector credentials, and verification.
Resolving a review as `revoke` does not itself change access.

```text
Reviewer approves revoke
        ↓
Administrator creates idempotent execution request
        ↓
Separate worker receives a source-specific adapter
        ↓
Adapter revokes upstream access using the idempotency key
        ↓
Adapter independently verifies the upstream state
        ↓
Athena revokes local grant and rematerializes provenance
```

## Safety invariants

- Only a resolved `revoke` case with an active, identified entitlement can create an execution.
- Creating and reading execution requests requires `athena-administrator`.
- One review case can create only one execution, and every idempotency key is globally unique.
- The API stores a request but exposes no endpoint that possesses connector write credentials.
- The adapter source must exactly match the grant source.
- Adapter retries receive the same idempotency key.
- A connector receipt is not success; independent verification must pass.
- Local grants remain active on execution or verification failure.
- Unexpected adapter exceptions are replaced with a generic message so secrets cannot enter evidence.
- Execution transition events are append-only in SQLAlchemy and immutable through a PostgreSQL trigger.

## Status model

| Status | Meaning |
|---|---|
| `pending` | Authorized request is waiting for a compatible worker |
| `running` | An adapter attempt has started |
| `succeeded` | Upstream revocation was independently verified |
| `failed` | The adapter failed; the request can be retried |
| `verification_failed` | The adapter returned but upstream removal could not be proven |

Replaying a succeeded execution is a no-op. Failed and verification-failed requests increment their
attempt count on retry while preserving all earlier transition events.

## API

Create a request after a review is resolved as `revoke`:

```http
POST /v1/executions
Authorization: Bearer <administrator-token>
Content-Type: application/json

{
  "case_id": "<review-uuid>",
  "idempotency_key": "ticket-1234-revoke-production-db"
}
```

Use `GET /v1/executions` or `GET /v1/executions/{execution_id}` for request, attempt, receipt,
verification, and failure evidence.

## Adapter contract

A separately deployed worker injects an adapter implementing:

```python
class RemediationAdapter(Protocol):
    source: str

    def revoke(self, target, idempotency_key: str) -> dict: ...
    def verify_revoked(self, target) -> VerificationResult: ...
```

Athena currently provides the durable framework and deterministic adapter tests, not production
GitHub or Azure write adapters. Those adapters require separately managed least-privilege credentials,
upstream API-specific idempotency behavior, and live verification before they can be enabled.
