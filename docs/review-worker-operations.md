# Review worker deployment and alert routing

This is an opt-in controlled-demo configuration. No worker, notification receiver,
or production service was started while preparing it. Production platform,
ownership and release gates remain unresolved in governance/readiness.json.

## Deployment artifact

Use `compose.review-worker.yaml` together with `compose.demo.yaml`. The overlay
reuses the API image and restricted `athena_app` login. It exposes no ports, drops
Linux capabilities, uses a read-only root filesystem, and writes its heartbeat
only to temporary storage. It does not run migrations or approve connector scopes.

Before starting it, validate the additive schema on a disposable database, confirm
the intended Athena tenant and approved Entra/subscription binding, and provide
the existing read-only collector credential through the deployment environment.
Required worker variables are `ATHENA_REVIEW_WORKER_TENANT`,
`ATHENA_AZURE_TENANT_ID`, `ATHENA_AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, and
`AZURE_CLIENT_SECRET`, in addition to the demo stack variables. Do not place
credential values in commands, logs, or version control. This demo overlay uses
environment credentials; production secret management remains a release gate.

Validate without printing the resolved configuration:

```powershell
docker compose -f compose.demo.yaml -f compose.review-worker.yaml config --quiet
```

After the deployment prerequisites have been met, the operator can start only the
worker and its PostgreSQL dependency:

```powershell
docker compose -f compose.demo.yaml -f compose.review-worker.yaml up -d --build review-worker
```

The image's non-root user runs one tenant's worker every 60 seconds. Use one worker
per tenant for this baseline. Restarting preserves pending work and attempt history
in PostgreSQL. Container health becomes unhealthy when the last completed sweep's
heartbeat is older than five minutes (after the configured health-check retries).
A collection failure still counts as a completed sweep; a database failure does
not refresh the heartbeat. Long-running collection can also make this health check
fail: measure collection duration before selecting production thresholds.
Docker restart policy restarts exited processes; it does not restart a process
solely because its health check fails. Supervisor handling of that condition must
be configured separately. Abrupt termination relies on existing lease recovery.

## Signals for an external log collector

Worker stdout contains JSON events. `review_worker_sweep` includes `tenant_id`,
UTC `at`, counts of attempted, failed, deferred, recorded-verification and exhausted
work, an `alerts` array, and `scan_complete`. `review_worker_error` includes only
tenant, timestamp and a fixed error code. Provider response bodies, credentials,
case IDs and identity attributes are not included.

| Signal | Suggested routing rule | Operator response |
|---|---|---|
| `retry_exhausted` in `alerts` | Open one incident per tenant and alert code; deduplicate repeated sweeps | Inspect affected cases and monitoring history; repair read-only scope/connector health, then explicitly request verification |
| `collection_failed` in `alerts` | Warn on repeated failures over several sweeps | Check provider availability and approved scope; automatic backoff remains active |
| `service_unavailable` error | Alert on repeated errors | Check database, schema and runtime configuration; no heartbeat refresh occurs |
| `heartbeat_unavailable` error | Alert immediately | Check temporary filesystem permissions/capacity |
| No sweep events or stale container heartbeat | Alert after the agreed collection-duration allowance | Check process supervision and stalled collection |

An exhausted count is a current observation of scanned cases, not a cumulative
counter. A sweep may stop at its attempt limit, so `scan_complete: false` must not
clear an existing tenant-wide alert merely because its observed exhausted count is
zero. Resolve exhaustion only after a complete sweep reports zero or an operator
checks the relevant case. `verification_recorded` counts recorded outcomes and
does not imply verified access removal.

Route these signals through the organization's existing log collector and receiver.
No receiver URL, Slack/email integration, or notification credentials are configured
here. A real delivery/deduplication/resolution drill, supervisor restart drill,
PostgreSQL/RLS concurrency checks and workload measurements remain open.

## Observed local validation

The merged Compose model passed `config --quiet` with synthetic values and no env
file. Tests cover exhaustion logging, database-error sanitization, heartbeat updates
and heartbeat write failures. No Docker image was built or container started;
Docker's Linux engine remains unavailable.
