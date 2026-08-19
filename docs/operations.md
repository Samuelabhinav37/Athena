# Operations, observability, backup, and recovery

## Request observability

Athena emits one JSON event per HTTP request through the `athena.requests` logger:

```json
{"event":"http_request","request_id":"demo-42","method":"GET","path":"/health","status":200,"duration_ms":1.234}
```

The event excludes query strings, headers, bodies, tokens, identity claims, and database content.
An incoming `X-Request-ID` is preserved only when it contains 1–128 safe alphanumeric, dot,
underscore, or hyphen characters; otherwise Athena generates a UUID. Every response returns the
effective request identifier.

Recommended alerts include sustained readiness failures, elevated 5xx rates, policy-engine errors,
failed monitoring runs, connector checkpoint staleness, review deadline breaches, and remediation
verification failures. Do not place secrets or full source payloads in labels or log fields.

## Security-event envelope

Athena's receiver-neutral security-event contract is documented in [telemetry.md](telemetry.md).
It aligns normalized timestamps, severity, resource, attributes, and trace context with
OpenTelemetry log concepts while retaining a digest and bounded provenance for the original source
bytes. The contract does not yet enable a listener, durable telemetry store, or external exporter.
Operators must not expose an ingestion port or forward events until the corresponding adapter,
authentication, rate limiting, retention, and failure behavior have been reviewed.

## Backup policy

PostgreSQL is Athena's system of record. Define recovery point and recovery time objectives before
production use. A minimum program should include encrypted scheduled backups, point-in-time recovery,
separate storage credentials, geographic or fault-domain separation, retention enforcement, access
logging, and periodic restore rehearsal.

The following examples are operator procedures, not autonomous agent actions. They touch the
database and require explicit human approval every time.

Logical backup to a pre-created protected directory:

```powershell
docker compose -f compose.demo.yaml exec -T postgres pg_dump --format=custom --no-owner --username athena --dbname athena > C:\secure-backups\athena.dump
```

Verify that the resulting archive is readable without restoring it:

```powershell
pg_restore --list C:\secure-backups\athena.dump
```

Never write backups inside the repository, container image, or CI artifacts. Treat them as highly
sensitive because they contain normalized identities, entitlements, decisions, and audit history.

## Restore rehearsal

A restore must target an isolated, empty rehearsal database—not the production system of record.
Resolve and verify the exact target before running any command. The high-level sequence is:

1. provision an isolated PostgreSQL instance with no production connector credentials;
2. restore the approved backup using `pg_restore`;
3. apply only forward migrations with `alembic upgrade head`;
4. run schema drift, integrity, append-only trigger, and security-gate checks;
5. compare expected identity, evidence, review, monitoring, and execution counts;
6. document achieved recovery time and recovery point; and
7. destroy the isolated rehearsal environment through the platform's approved process.

Never use `alembic downgrade`, `DROP`, `TRUNCATE`, destructive volume commands, or a restore over
live Athena data. Disaster recovery does not authorize real connector actions; execution adapters
remain separately credentialed and approved.
