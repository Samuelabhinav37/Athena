# Production deployment and recovery plan

## Status and authority boundary

This is the proposed Azure production baseline. It is planning material, not deployment evidence and
not authorization to create resources, incur cost, apply migrations, change connector access, copy
evidence, or enable remediation executors. `governance/readiness.json` remains
`production_status: blocked` until every acceptance gate below has reviewed evidence.

The operator must first approve the subscription, primary and recovery regions, cost envelope,
resource names, DNS zone, data classification, owners, and recovery objectives. Athena's current
contract sets an RPO of 15 minutes, an RTO of 120 minutes, and a restore-test interval of 30 days.

## Proposed Azure baseline

| Concern | Proposed service and control | Required evidence |
|---|---|---|
| API and web | Zone-redundant Azure Container Apps environment; at least two API replicas; separate web app; readiness probes; multiple-revision promotion | Resource export, revision and replica configuration, probe results, controlled rollback record |
| Images | Private Azure Container Registry; CI-produced API/web images addressed by manifest digest; production manifests locked against overwrite and deletion | Source commit, SBOM, CI URLs, vulnerability result, image digests, ACR lock state |
| Database | Private Azure Database for PostgreSQL Flexible Server, PostgreSQL 16, zone-redundant HA, encrypted transport, 35-day backup retention | Configuration export, HA/failover result, TLS connection proof, migration and drift reports |
| Recovery | Point-in-time restore to a new isolated server; optional geo-redundant backup only after residency approval; monthly restore rehearsal | Restore point, achieved RPO/RTO, restored counts, integrity/immutability/security-gate reports, teardown approval |
| Secrets | Azure Key Vault references consumed through a dedicated managed identity; least-privilege secret-reader role; documented rotation and break-glass custody | Role assignments, secret references without values, rotation test, custodian approval |
| Identity | Production OIDC issuer and audience, dedicated Athena tenant claim, administrative group mapping, two named break-glass custodians | Issuer metadata digest, role mapping review, negative authorization tests, break-glass exercise audit |
| Network | HTTPS-only external ingress; private database and Key Vault paths; no public PostgreSQL; restricted egress for approved connectors | Network diagram, DNS/TLS validation, public-access denial tests, connector allowlist |
| Observability | Log Analytics and Azure Monitor diagnostic settings, alerts, action groups, dashboards, retention, and on-call ownership | Query results, alert-fire and delivery tests, dashboard export, owner and escalation record |

Azure Container Apps supports revision readiness and controlled traffic movement, managed identities
can retrieve Key Vault references, and a zone-redundant environment with multiple replicas provides
the intended application availability model. See Microsoft's documentation for
[revisions](https://learn.microsoft.com/en-us/azure/container-apps/revisions),
[reliability](https://learn.microsoft.com/en-us/azure/reliability/reliability-container-apps), and
[Key Vault secret references](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets).

Azure Database for PostgreSQL Flexible Server supports synchronous zone-redundant HA and point-in-time
restore to a newly named server. Backup retention is limited to 35 days; geo-redundant backup must be
selected at server creation and can change residency. See the official
[HA](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-high-availability)
and [backup/restore](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore)
contracts.

## Ordered work plan

### 1. Approve the deployment envelope

Record these decisions before infrastructure code is written:

- Azure subscription and billing owner;
- primary region and whether a paired-region copy is legally permitted;
- development, staging, and production isolation model;
- DNS name and certificate owner;
- monthly cost ceiling and scaling limits;
- service owner, security owner, database owner, and two break-glass custodians;
- alert destinations and on-call escalation path; and
- confirmed RPO, RTO, retention, and evidence-residency requirements.

Exit gate: every value is explicit, reviewed, and contains no secret material.

### 2. Build reviewed infrastructure as code

Create a dedicated `infra/azure` module only after step 1 is approved. It should declare resource
groups, virtual networking, private DNS, Container Apps, ACR, Key Vault, PostgreSQL, Log Analytics,
diagnostic settings, alerts, action groups, managed identities, and least-privilege role assignments.
Separate environment parameter files must contain identifiers and sizing only—never secret values.

Exit gate: lint and validation pass; a plan against the approved subscription has no unexpected
deletion, public database endpoint, broad role assignment, or unbounded scale setting.

### 3. Establish the image promotion chain

Build once from a reviewed commit. Retain the security-gate URL, supply-chain URL, CycloneDX SBOM,
scan result, and API/web manifest digests. Push to ACR, deploy only by digest, and lock the promoted
manifests. ACR tags are mutable by default, so a tag alone is not release identity. Microsoft
documents digest addressing and [image locking](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-image-lock).

Exit gate: the running revision digests exactly match the signed promotion record and no high or
critical fixable finding lacks an approved, expiring exception.

### 4. Provision data and identity boundaries

Provision PostgreSQL before applications, but do not load Athena evidence yet. Create separate
migration and runtime identities, store their secrets in Key Vault, and expose only Key Vault
references to Container Apps. Configure the production OIDC issuer, audience, tenant claim, roles,
key rotation, and break-glass process. Apply forward migrations only under a separately approved
migration plan.

Exit gate: runtime cannot assume the migration role, bypass RLS, access another tenant, or retrieve
unrelated secrets; administrators cannot bypass tenant isolation.

### 5. Deploy staging and prove scale behavior

Deploy staging with production-equivalent topology and synthetic data. Set
`ATHENA_SHARED_REQUEST_CONTROLS_ENABLED=true` and declare the actual worker and replica counts. Run
authentication, cross-tenant denial, connector-scope, atomic replay, rate-limit, monitoring-lease,
readiness, rolling-revision, rollback, and dependency-failure tests.

Exit gate: at least two API replicas produce one shared rate-limit/replay outcome, monitoring work is
not duplicated, an unhealthy revision receives no production traffic, and rollback preserves the
database contract.

### 6. Prove backup and recovery

Create a recovery point from staging or an approved sanitized production-like dataset. Restore to a
new isolated PostgreSQL server with no production connector credentials. Reapply only forward
migrations, then run tenant integrity, RLS/privilege checks, append-only mutation denials, row-count
reconciliation, Alembic drift, and the deterministic security gate. Record timestamps and calculate
achieved RPO and RTO. A restored HA source returns as a single instance, so re-enable HA explicitly
before any promoted cutover.

Exit gate: achieved RPO is at most 15 minutes, RTO is at most 120 minutes, evidence counts and
digests reconcile, immutable mutations fail, and the isolated target is removed only through a
separately approved teardown.

### 7. Prove operations and incident response

Route Container Apps and PostgreSQL diagnostics to Log Analytics. Implement alerts for readiness,
5xx rate, connector freshness, monitoring lease expiry, policy failures, database availability,
backup health, and remediation verification failure. Deliver them through reviewed Azure Monitor
action groups; test each notification path. Microsoft documents
[Container Apps secure diagnostics](https://learn.microsoft.com/en-us/azure/container-apps/secure-deployment)
and [Azure Monitor action groups](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/action-groups).

Exit gate: alert simulations reach the named on-call owner, runbooks identify decision authority,
and logs contain request IDs without secrets, tokens, query strings, or source payloads.

### 8. Production promotion review

Reconcile the completed evidence against `governance/production-evidence.example.json`. A human
reviewer confirms all digests and approvals before changing the canonical manifest to
`production_status: ready`. Production migration and connector synchronization require their own
explicit approvals. Destructive remediation remains pending until a separately authorized executor
acts and verifies the result.

## Deliberately deferred

- GitHub and Azure remediation write adapters;
- durable security-event ingestion and acknowledged delivery;
- OSCAL Assessment Results, PDF, and Word renderers; and
- multi-region active/active application and database writes.

These are product or resilience expansions, not prerequisites for the proposed single-region,
zone-redundant production baseline.
