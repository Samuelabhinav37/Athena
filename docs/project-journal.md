# Athena project journal

This document is Athena's living engineering record. Update it whenever a milestone changes the architecture, introduces a decision, encounters a meaningful problem, or produces new validation evidence.

Last updated: August 16, 2026

## Project objective

Athena is an open-source identity-governance platform for continuous authorization provenance and compliance evidence. For every identity, the system should answer:

1. Who are you?
2. What can you access?
3. Why can you access it?
4. Are you still supposed to have that access?
5. Can the decision and its history be proven to an auditor?

The governing safety rule is:

> The LLM explains. ML recommends. The policy engine decides. A human approves destructive actions.

## Current status

**Active milestone:** Milestone 2 — canonical identity model and persistence

**Completed:**

- GitHub repository and local working directory
- Initial project structure and documentation
- FastAPI health endpoint
- Local Docker Compose foundation
- Controlled Keycloak Acme Corp identity lab
- Automated structural validation for the seeded realm
- Validated application settings and PostgreSQL session management
- Canonical identity, group, and role persistence models
- Initial Alembic migration and identity read API
- Dedicated Keycloak collector service account
- Idempotent Keycloak-to-PostgreSQL identity synchronization

**Next outcome:** Athena models resources, entitlements, grants, provenance edges, and audit events so every effective permission can be traced to its source.

## Roadmap

| Milestone | Outcome | Status |
|---|---|---|
| 0. Repository foundation | Reproducible project structure, standards, and documentation | Complete |
| 1. Controlled identity lab | Version-controlled Keycloak realm with known ground truth | Complete |
| 2. Identity backbone | Canonical schemas, PostgreSQL persistence, migrations, and ingestion | In progress |
| 3. Authorization provenance | Trace every effective entitlement to its source | Planned |
| 4. Deterministic security | OPA policies, tests, CI security gate, and NIST mappings | Planned |
| 5. Risk analytics | Identity drift, peer analysis, and explainable access decay | Planned |
| 6. Explain and present | Ollama explanations, React dashboard, and evidence report | Planned |

## Work completed

### Repository foundation

The GitHub repository is [Samuelabhinav37/Athena-](https://github.com/Samuelabhinav37/Athena-), cloned locally at `C:\Users\samue\Athena`.

Added:

- `README.md` with the product description, MVP, architecture, and local setup;
- `docs/architecture.md` with trust boundaries, canonical concepts, and acceptance criteria;
- `CONTRIBUTING.md` and `SECURITY.md`;
- Apache 2.0 licensing;
- `.gitignore`, `.editorconfig`, `.gitattributes`, and `.env.example`;
- Python packaging and development dependencies in `pyproject.toml`;
- the initial FastAPI application and `/health` endpoint;
- PostgreSQL, Keycloak, and OPA services in `compose.yaml`; and
- initial API, web, infrastructure, policy, and test directories.

Published commits:

- `3779679` — Initialize Athena project foundation
- `ed9d88e` — Define repository line endings

### Controlled identity lab

Added a version-controlled Keycloak realm at `infra/keycloak/realm-athena.json`.

The Acme Corp baseline contains:

| Identity | Department | Initial access context |
|---|---|---|
| Alice | Engineering | Developer |
| Bob | DevOps | DevOps and Cloud Admin |
| Charlie | Security | Security Analyst |
| David | Finance | Finance Analyst |
| Emma | HR | HR Specialist |
| Frank | IT | Athena Administrator, DB Admin, and Cloud Admin |

The realm also includes:

- departmental groups for Engineering, Finance, HR, Security, DevOps, and IT;
- nine business and administrative roles;
- a bearer-only `athena-api` OIDC client;
- a public `athena-web` client using Authorization Code flow with PKCE;
- department, manager, and group token claims;
- temporary credentials restricted to the disposable local lab;
- disabled public registration and password grants; and
- Keycloak brute-force protection.

Docker Compose imports the realm automatically the first time Keycloak starts. Tests verify the expected identities, departments, governance attributes, temporary credentials, and secure client configuration.

Published commit:

- `5bf392a` — Add controlled Keycloak identity lab

### Canonical identity persistence — first vertical slice

Added the stable foundation that later ingestion and provenance records will use:

- validated `ATHENA_` environment settings;
- cached SQLAlchemy engine and request-scoped sessions;
- canonical `Identity`, `Group`, and `Role` models;
- many-to-many identity/group and identity/role relationships;
- stable UUID primary keys and source/external-ID uniqueness constraints;
- portable JSON metadata with PostgreSQL JSONB storage;
- explicit human, service-account, application, workload, API-client, and agent identity types;
- Alembic configuration and migration `20260816_01`;
- `/ready` database readiness endpoint;
- paginated `GET /v1/identities` endpoint;
- `GET /v1/identities/{identity_id}` detail endpoint; and
- isolated API and model tests using the same SQLAlchemy metadata.

This slice intentionally stops before Keycloak ingestion and entitlement modeling. It establishes and verifies stable identity keys first, reducing migration churn in the relationships that will reference them.

Published commit:

- `6e36038` — Add canonical identity persistence layer

### Keycloak ingestion vertical slice

Added an end-to-end identity-source path from the controlled realm into PostgreSQL:

- dedicated `athena-collector` client-credentials service account;
- four explicit Keycloak view/query management roles and no mutation roles;
- secret-backed collector configuration that does not expose credentials in output;
- Keycloak Admin API client with timeouts, pagination, and safe error translation;
- source-neutral normalized identity, group, and role contracts;
- filtering of service-account users and Keycloak internal roles from the human baseline;
- transactional upserts keyed by source and external ID;
- exact replacement of current group and role relationships;
- transaction-local membership caches that prevent duplicate shared groups and roles;
- manual `python -m athena.cli sync-keycloak` command;
- concise operational failures without credential or token output; and
- automated collector, synchronization, CLI, realm, model, and API tests.

Published commit:

- `3f601b0` — Add idempotent Keycloak identity ingestion

## Architecture decisions

### PostgreSQL is authoritative for the MVP

The original architecture includes PostgreSQL and Neo4j. The MVP will use PostgreSQL as its system of record and represent provenance relationally. Neo4j will be introduced through an adapter when attack-path queries justify the additional operational complexity.

### The initial role-change scenario begins from clean ground truth

Alice is seeded as an Engineering developer. Her later transfer to Security will be represented as a separate event. This makes retained access detectable and keeps the seed data from silently containing the condition Athena is supposed to discover.

### Deterministic systems retain authority

OPA/Rego will make policy decisions. Analytics will provide explainable risk recommendations. Ollama will translate structured results into human-readable explanations. Neither ML nor the LLM may change access or override policy.

### Destructive remediation remains human-controlled

Version 0.1 records recommendations and reviewer decisions. It does not remove privileges without explicit, auditable human approval.

### The repository uses HTTPS for Git operations

The supplied SSH remote could not authenticate on this machine. The local repository therefore uses the equivalent HTTPS remote. This does not change repository ownership or content.

## Problems encountered and resolutions

### Downloads file reads stalled inside the restricted shell

**Symptom:** Reading the original architecture plan from `Downloads` repeatedly stalled.

**Cause:** The restricted execution path could not complete the read reliably.

**Resolution:** The read was retried with explicit filesystem approval and completed successfully.

**Lesson:** If a user-provided file outside the active repository stalls under the restricted runner, verify the exact path and request narrowly scoped read access instead of moving or duplicating the file.

### GitHub CLI was unavailable

**Symptom:** `gh auth status` failed because `gh` was not installed.

**Resolution:** Standard Git commands were used for repository access, commits, and publishing. No GitHub CLI dependency was added to the project.

### SSH authentication failed

**Symptom:** The supplied remote returned `Permission denied (publickey)`.

**Cause:** This machine did not have a GitHub-authorized SSH key available.

**Resolution:** The repository was cloned and configured using HTTPS:

```text
https://github.com/Samuelabhinav37/Athena-.git
```

### Git author identity was missing

**Symptom:** Git had no configured author name or email.

**Resolution:** A repository-local identity was configured rather than modifying the global Git configuration:

```text
Samuelabhinav37 <Samuelabhinav37@users.noreply.github.com>
```

### Windows line-ending warnings appeared

**Symptom:** Git warned that LF content could be replaced with CRLF in the working copy.

**Resolution:** `.gitattributes` now defines LF endings for source code, policies, configuration, and documentation. `.editorconfig` provides matching editor guidance.

### Docker Desktop was installed but stopped

**Symptom:** Docker commands could not connect to `dockerDesktopLinuxEngine`.

**Resolution:** Docker Desktop was started in the background. The engine became available with server version `29.7.2`, after which Keycloak could be pulled and launched.

### Pytest was not installed

**Symptom:** The system Python reported `No module named pytest`.

**Resolution:** A repository-local `.venv` was created and the declared `.[dev]` dependencies were installed. The virtual environment is excluded from Git.

### Ruff found import-order violations

**Symptom:** Linting reported two `I001` findings in test modules.

**Resolution:** Ruff applied its deterministic import sorting, after which the entire lint suite passed.

### FastAPI test tooling emits an upstream warning

**Symptom:** Tests emit a `StarletteDeprecationWarning` explaining that the current `TestClient` integration with `httpx` is deprecated in favor of `httpx2`.

**Status:** Open, non-blocking. All tests pass. This comes from the installed FastAPI/Starlette dependency stack rather than Athena code.

**Planned resolution:** Revisit the test client when FastAPI's supported dependency path stabilizes. Do not suppress the warning without understanding the migration path.

### SQLite serialized a timestamp without a UTC suffix

**Symptom:** The first identity API test failed because the in-memory SQLite test database returned a timezone-naive timestamp while PostgreSQL preserves timezone-aware values.

**Resolution:** The test now verifies that a non-empty serialized observation time is present without asserting a dialect-specific suffix. PostgreSQL remains the authoritative production behavior and was validated separately.

### Migration drift detected an inconsistent enum constraint

**Symptom:** `alembic check` reported that the live database contained an identity-type check constraint absent from ORM metadata.

**Cause:** SQLAlchemy's non-native Enum constraint behavior differed between the explicit migration and the model metadata used by Alembic comparison.

**Resolution:** The allowed identity types are now represented by the same explicit, named check constraint in both the ORM model and migration. The empty development schema was rolled back and rebuilt, after which `alembic check` reported no upgrade operations.

### New migration files triggered Windows line-ending warnings

**Symptom:** Git warned about CRLF conversion for Alembic `.ini` and `.mako` files.

**Resolution:** `.gitattributes` now explicitly keeps both file types at LF, matching the rest of Athena's source and configuration.

### Keycloak cold start exceeded the first readiness window

**Symptom:** The recreated Keycloak container did not publish the realm within the first 60 seconds.

**Cause:** First-start Quarkus augmentation and Keycloak database-schema initialization took longer than the original readiness window. Logs showed normal initialization rather than an import failure.

**Resolution:** The existing container was left running and checked for another bounded interval. The realm became ready without configuration changes. Future live checks allow up to 120 seconds for a cold start.

### Collector service account received HTTP 403

**Symptom:** Client-credentials authentication succeeded, but `GET /admin/realms/athena/users` returned `403 Forbidden`. No records were written to PostgreSQL.

**Cause:** The service account had the four correct `realm-management` roles, but `fullScopeAllowed: false` kept those assigned roles out of its access token because separate role scope mappings were not configured.

**Resolution:** Full scope was enabled only for the dedicated collector client. This includes all roles assigned to that service account in its token but grants no additional roles; the account still has only `query-groups`, `query-users`, `view-realm`, and `view-users`. After recreating the disposable realm, the collector succeeded.

## Verification record

### Repository foundation

- Python source compilation: passed
- Docker Compose configuration parsing: passed
- Git whitespace validation: passed
- Initial branch pushed and synchronized with `origin/main`

### Controlled identity lab

- JSON syntax validation: passed
- Ruff linting: passed
- Automated tests: 6 passed
- Docker Compose configuration parsing: passed
- Live Keycloak realm import: passed
- OIDC discovery endpoint: `http://localhost:8080/realms/athena/.well-known/openid-configuration`
- Admin API user check: Alice, Bob, Charlie, David, Emma, and Frank confirmed
- Alice baseline `developer` role: confirmed

### Canonical identity persistence

- Ruff linting: passed
- Automated tests: 10 passed
- Offline migration SQL generation: passed
- Live PostgreSQL migration `20260816_01`: applied
- Created tables: `groups`, `identities`, `identity_groups`, `identity_roles`, and `roles`
- Alembic model/schema drift check: no new upgrade operations
- API database readiness result: `{"status": "ready", "database": "available"}`
- Git whitespace validation: passed

### Keycloak identity ingestion

- Ruff linting: passed
- Automated tests: 14 passed
- Realm JSON validation: passed
- Dedicated service-account authentication: passed
- First live synchronization: 6 created, 0 updated
- Second live synchronization: 0 created, 6 updated
- Stable database counts: 6 identities, 6 groups, 8 assigned roles
- Stable relationship counts: 6 identity/group and 9 identity/role memberships
- Live API assertion: Alice is human, belongs to Engineering, and holds Developer
- Alembic model/schema drift check: no new upgrade operations
- Failed 403 attempts wrote zero records, preserving transaction safety

## Current local environment

- Repository: `C:\Users\samue\Athena`
- Branch: `main`
- Remote: `origin` over HTTPS
- Python environment: `.venv`
- Docker Desktop: installed and started during Milestone 1 validation
- Keycloak: started through Docker Compose on port `8080`
- PostgreSQL: started through Docker Compose on port `5432`, migration `20260816_01` applied

Local runtime state is not source-controlled and may differ between development sessions. Use commands such as `git status`, `docker compose ps`, and the automated test suite to confirm current state rather than relying only on this snapshot.

## Next work: authorization provenance foundation

The next slice should:

1. define canonical resources and permissions;
2. represent direct and inherited grants separately from effective entitlements;
3. model ordered provenance edges from identity through group/role to permission and resource;
4. store business justification, requester, approver, grant time, and expiration;
5. flag privileged access missing required governance attributes;
6. introduce append-only audit events for ingestion and state transitions;
7. seed Alice's initial GitHub and development access;
8. return a human-readable provenance chain through the API; and
9. prove that an auditor can reconstruct why Alice has one selected permission.

## Journal update checklist

At the end of each meaningful change:

- update the current milestone and roadmap status;
- record delivered behavior and relevant commit identifiers;
- document architectural decisions and why they were made;
- record meaningful failures, root causes, and resolutions;
- add exact validation evidence;
- list known warnings or incomplete checks; and
- define the next smallest end-to-end outcome.
