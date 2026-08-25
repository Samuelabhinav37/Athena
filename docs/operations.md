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

## Monitoring leases

Each schedule slot is claimed with a database lease before connector or policy work begins. The
default lease is 900 seconds and can be configured with `ATHENA_MONITORING_LEASE_SECONDS` between
60 and 86400 seconds. Athena heartbeats immediately before and after every monitoring operation.
A second worker fails closed while the lease is live; an expired or legacy missing lease is retried
as a new attempt only after an immutable `lease_recovery` monitoring step records the interruption.

Lease tokens are internal coordination values and are not returned by monitoring routes or written
to step output. Successful and failed terminal transitions clear the ownership token and expiry,
while retaining the last heartbeat for diagnostics. Set the lease longer than the maximum expected
duration of any single connector operation; a provider call that outlives the lease can be safely
reclaimed and its original worker will lose authority to append later evidence.

## Security-event envelope

Athena's receiver-neutral security-event contract is documented in [telemetry.md](telemetry.md).
It aligns normalized timestamps, severity, resource, attributes, and trace context with
OpenTelemetry log concepts while retaining a digest and bounded provenance for the original source
bytes. Authenticated HTTP normalization routes exist for bounded JSON, OTLP/JSON, and syslog input,
plus a signed generic webhook route. They do not provide a durable telemetry store or acknowledged
external delivery. Operators must not treat normalization success as ingestion durability.

The initial JSON normalization endpoint is administrator-protected and rate-limited, but it does
not persist events. Do not treat `200` as durable ingestion. Development may use the built-in
process-local window only in a one-worker, one-replica topology. Production and multi-replica
deployments must enable Athena's PostgreSQL-backed shared request controls; a gateway may add a
separate perimeter limit but does not replace Athena's tenant-scoped control.

The OTLP/JSON endpoint shares the same administrator authentication, selected request limiter, 1 MiB
request bound, no-store response policy, and non-persistence boundary. It is not a standard
`/v1/logs` collector endpoint. Configure test clients with Athena's explicit normalization URL and
do not interpret accepted-record counts as durable storage acknowledgements.

The syslog endpoint accepts a single RFC 5424 message for authenticated normalization. It does not
open a syslog socket, accept UDP, terminate TLS, or authenticate the HOSTNAME embedded in a message.
Do not expose port 514 or route device traffic directly to Athena. Production syslog transport
requires a separately reviewed TLS listener or authenticated gateway that supplies peer identity.

The generic webhook route remains hidden unless `ATHENA_WEBHOOK_ENABLED=true`. Configure a distinct
secret of at least 32 characters through `ATHENA_WEBHOOK_SECRET`; never place it in source control or
request content. The five-minute freshness check is local clock validation. Replay protection uses
the process-local cache in development or tenant-scoped PostgreSQL reservations when shared request
controls are enabled. Production requires the shared mode and an explicit secret-rotation procedure.

The deterministic JSON exporter returns bytes to its caller but does not write or send them. Treat
export packages as sensitive because normalized event bodies and provenance may contain identity or
security context. Operators must choose an approved encrypted destination and independently verify
the package digest before retention or onward transfer.

The deterministic OTLP/HTTP JSON exporter has the same in-memory boundary. Review every returned
mapping warning before transmission; a null body value is omitted and an integer outside signed
64-bit range is converted to a decimal string. The adapter does not configure TLS, credentials,
collector allowlists, retries, queues, or delivery acknowledgement. Those controls are required in
a separately reviewed transport before any production destination is used.

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
# Disposable PostgreSQL verification

Run `powershell -File scripts/test-postgres.ps1` to create an isolated Compose project, apply every
migration, run PostgreSQL privilege and tenant-isolation tests, and then remove only that randomly
named test project's containers and volume. The workflow never connects to the normal Athena
Compose project or its evidence volume.

Production replicas must set `ATHENA_SHARED_REQUEST_CONTROLS_ENABLED=true` after migrations
`20260824_20` and `20260824_21` are approved and applied. Until then Athena deliberately permits only
one worker and one replica because telemetry throttling and webhook replay protection use bounded
in-process adapters. Production configuration fails closed if shared controls are disabled.
