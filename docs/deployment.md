# Deployment and demonstration baseline

Athena provides reproducible API and web images plus a health-dependent local demonstration stack.
This baseline is suitable for controlled evaluation; it is not a claim that the development
Keycloak realm or single-host Compose topology is production-ready.

## Images

| Component | Build file | Runtime |
|---|---|---|
| API | `apps/api/Dockerfile` | Python 3.13.14 slim Bookworm, UID/GID 10001 |
| Web | `apps/web/Dockerfile` | Node 24.14.1 build; NGINX 1.29.8 runtime as `nginx` |

The web filesystem is read-only in the demo stack, with `/tmp` supplied as a temporary filesystem.
NGINX serves the React application on port 8080 and proxies `/v1/` to the API, keeping browser API
requests same-origin. The API runs with Uvicorn access logging disabled because Athena emits its own
bounded structured request event.

## Controlled demo

Create a local `.env` from `.env.example` and replace every default password. At minimum, the demo
stack requires non-empty values for:

```dotenv
POSTGRES_PASSWORD=<local-demo-password>
ATHENA_APP_DB_PASSWORD=<separate-local-runtime-password>
KEYCLOAK_ADMIN=<local-demo-administrator>
KEYCLOAK_ADMIN_PASSWORD=<local-demo-password>
```

Validate the model before starting anything:

```powershell
docker compose -f compose.demo.yaml config --quiet
```

Build and start the infrastructure only after reviewing resolved configuration:

```powershell
docker compose -f compose.demo.yaml build
docker compose -f compose.demo.yaml up -d postgres keycloak opa
```

Applying migrations changes the database and therefore requires explicit operator approval:

```powershell
docker compose -f compose.demo.yaml --profile migration run --rm migrate
docker compose -f compose.demo.yaml up -d api web
```

The migration profile never runs as an API dependency. Starting or restarting the application does
not authorize a schema change; an operator must invoke the profile explicitly after reviewing the
forward migration plan and obtaining approval.

Fresh PostgreSQL volumes provision the restricted `athena_app` login from
`infra/postgres/init-runtime-role.sh`. Existing PostgreSQL volumes do not rerun initialization
scripts. Before upgrading such a volume to the separated runtime identity, an authorized operator
must provision or rotate the runtime password interactively so it is not placed in shell history:

```powershell
docker compose -f compose.demo.yaml exec postgres psql --username athena --dbname athena
```

At the `psql` prompt, run `\password athena_app`, enter the same separately managed value supplied
as `ATHENA_APP_DB_PASSWORD`, exit, and only then invoke the approved migration profile. Do not put
the password in the command line, logs, repository, or migration file.

Open <http://localhost:3000>. Keycloak remains at <http://localhost:8080>. PostgreSQL and OPA are
not published to the host by this stack.

The containerized API intentionally does not connect to a remote Ollama service. Athena's current
explanation boundary permits only loopback inference, so live explanations require a co-located
runtime design or running the API and Ollama together outside this Compose topology. Do not broaden
the allowed destination merely to make a demo work.

## Health model

- `/health` proves the API process can respond.
- `/ready` proves the API can query PostgreSQL.
- the web `/healthz` endpoint proves NGINX can respond.
- Compose starts API only after PostgreSQL, Keycloak, and OPA report healthy, and starts web only
  after API readiness succeeds.

## Production requirements

`ATHENA_ENV=production` fails startup when authentication is disabled, the default database
credential or Keycloak collector secret remains, the OIDC issuer is not HTTPS, shared database
request controls are disabled, or the checked-in tenant-isolation plan is not `ready`. The tenant
isolation implementation is ready; the canonical release manifest remains production-blocked until
deployment and recovery evidence is supplied. A production deployment must provide:

- externally managed PostgreSQL with encrypted connections, backups, and point-in-time recovery;
- production-mode Keycloak behind TLS, without the imported demonstration realm or default users;
- an ingress or gateway that terminates TLS and supplies trusted forwarding headers;
- a secret manager or workload identity rather than environment files committed to source;
- immutable image digests, vulnerability and SBOM scanning, and a promotion process;
- centralized logs, alerting, availability objectives, and incident response ownership; and
- separately authorized migration, backup, restore, and remediation-executor procedures.

All deployments must declare `ATHENA_API_WORKER_COUNT` and `ATHENA_API_REPLICA_COUNT` to match the
actual process and platform topology. Development may use the bounded process-local request controls
only with one worker and one replica. Production requires
`ATHENA_SHARED_REQUEST_CONTROLS_ENABLED=true`, which uses the tenant-scoped PostgreSQL replay and
rate-limit tables created by migrations `20260824_20` and `20260824_21` and permits a declared
multi-worker or multi-replica topology.

The proposed Azure service mapping, approval boundaries, recovery rehearsal, and production
acceptance sequence are maintained in the
[production deployment and recovery plan](production-deployment-plan.md).
