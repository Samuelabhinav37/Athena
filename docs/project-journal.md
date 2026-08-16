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

**Active milestone:** Milestone 5 — risk analytics

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
- Canonical resources, permissions, grants, and effective entitlements
- Ordered authorization provenance and governance-gap detection
- Append-only audit events protected by PostgreSQL
- Deterministic OPA decisions with structured policy violations
- Immutable, versioned policy evaluation evidence
- GitHub Actions security gate with immutable action pins
- Executable allow/deny fixtures and security evidence artifacts
- Initial NIST AC-2, AC-5, and AC-6 continuous-control mappings
- Immutable identity role-transition history and access observations
- Explainable access-decay scoring with Security peer comparison

**Next outcome:** Athena establishes a reproducible entitlement-anomaly baseline and compares Alice with a meaningful synthetic peer cohort using Isolation Forest.

## Roadmap

| Milestone | Outcome | Status |
|---|---|---|
| 0. Repository foundation | Reproducible project structure, standards, and documentation | Complete |
| 1. Controlled identity lab | Version-controlled Keycloak realm with known ground truth | Complete |
| 2. Identity backbone | Canonical schemas, PostgreSQL persistence, migrations, and ingestion | Complete |
| 3. Authorization provenance | Trace every effective entitlement to its source | Complete |
| 4. Deterministic security | OPA policies, tests, CI security gate, and NIST mappings | Complete |
| 5. Risk analytics | Identity drift, peer analysis, and explainable access decay | In progress |
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

### Authorization provenance foundation

Added the first complete access explanation path:

- canonical resources with type and sensitivity;
- resource-scoped permissions with privileged-access classification;
- direct identity, inherited group, and inherited role grants;
- a database constraint requiring exactly one subject per grant;
- requester, approver, business reason, policy, grant, expiration, and revocation fields;
- derived effective entitlements separated from assigned grants;
- deterministic ordered provenance edges;
- governance-gap detection for missing justification, approval, and privileged expiration;
- an entitlement API at `GET /v1/identities/{identity_id}/entitlements`;
- append-only audit events protected by ORM listeners and a PostgreSQL trigger; and
- an idempotent `python -m athena.cli seed-provenance-demo` scenario command.

Alice's controlled scenario contains governed GitHub Write and Development Database Read access inherited through Developer, plus direct Production Database Read access. Production access is deliberately ungoverned because its business reason and expiration are missing.

Published commit:

- `fbcecec` — Add authorization provenance foundation

### Deterministic OPA policy enforcement

Added the first policy decision and evidence loop:

- versioned policy-input schema for identity, resource, permission, governance, authentication, and provenance;
- Rego rules for ungoverned privileged access, phishing-resistant privileged MFA, developer Payroll restrictions, and requester/approver separation of duties;
- five Rego unit tests covering pass and failure cases;
- OPA client with explicit timeouts and strict response validation;
- fail-closed behavior that stores `POLICY_ENGINE_UNAVAILABLE` rather than implicitly passing;
- SHA-256 policy-bundle versioning over enforceable Rego files;
- immutable policy evaluation records containing input snapshots and structured violations;
- stable active/inactive entitlement lifecycle so evaluation history survives rematerialization;
- PostgreSQL trigger and ORM protection against evaluation mutation;
- `python -m athena.cli evaluate-policies --username alice`; and
- `GET /v1/identities/{identity_id}/policy-evaluations`.

Alice's two non-privileged entitlements pass. Production Database Read fails for missing governance evidence and missing phishing-resistant authentication context. OPA returns decisions only and has no remediation credentials.

Published commit:

- `def83b2` — Add deterministic OPA policy enforcement

### CI security gate and NIST mappings

Added the merge-time enforcement and evidence layer:

- GitHub Actions workflow for Python linting and tests, Compose validation, live PostgreSQL migrations, Alembic drift detection, Rego tests, and the deterministic security gate;
- read-only workflow permissions and concurrency cancellation;
- official GitHub actions pinned to immutable commits corresponding to checkout v7.0.1, setup-python v7.0.0, and upload-artifact v7.0.1;
- four executable fixtures covering governed access, ungoverned production access, developer Payroll access, and requester/approver conflict;
- exact matching of expected allow/deny decisions and violation codes;
- deterministic JSON and Markdown evidence reports;
- artifact upload and GitHub job-summary publication even when the gate fails;
- machine-readable partial mappings for NIST AC-2, AC-5, and AC-6;
- validation that referenced tests, fixtures, and Rego rules still exist; and
- documented branch-protection recommendations.

The first hosted GitHub Actions run completed successfully:

- Run ID: `31977841305`
- Commit: `09ec648981ddfa42918944b1acc4d8b977f157f3`
- Result: success
- URL: `https://github.com/Samuelabhinav37/Athena-/actions/runs/31977841305`

Published commit:

- `09ec648` — Add CI security gate and NIST mappings

### Identity drift and access-decay analytics

Added the first explainable risk-assessment path:

- immutable Engineering-to-Security role-transition records;
- append-only audit evidence containing before-and-after identity state;
- idempotent last-use observations for each retained entitlement;
- stable retained downstream access while the authoritative identity role changes;
- current-department peer selection with explicit peer membership;
- deterministic weighted factors for retained access, privilege, resource sensitivity, time since use, peer deviation, policy risk, and authentication risk;
- normalized 0–100 entitlement scores with database range constraints;
- low, medium, high, and critical risk levels;
- immutable, versioned identity assessments and per-entitlement findings;
- `python -m athena.cli apply-drift-demo`;
- `python -m athena.cli assess-risk --username alice`; and
- `GET /v1/identities/{identity_id}/risk-assessments`.

Alice transfers to Security while three downstream entitlements remain active. Charlie is her current Security peer. None of Alice's retained permissions appear in Charlie's baseline, and Production Database Read reaches 100/100 because every factor is maximized. The identity assessment is therefore `critical`.

Published commit:

- `aa33d59` — Add identity drift and access-decay analytics

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

### Provenance model failed to import because of a namespace collision

**Symptom:** Test collection and Alembic loading failed with `TypeError: 'MappedColumn' object is not callable`.

**Cause:** The `ProvenanceEdge.relationship` column shadowed SQLAlchemy's imported `relationship()` function inside the class body.

**Resolution:** The Python attribute became `relationship_type` while remaining mapped to the database column `relationship`. The API uses a validation alias so clients continue to receive the natural field name `relationship`.

### Inline live API assertion was misparsed by PowerShell

**Symptom:** The provenance seed and database counts passed, but a follow-up inline Python API assertion failed before execution with a PowerShell `ScriptBlock` parsing error.

**Cause:** Nested double quotes and an f-string were not shell-safe in the PowerShell command argument.

**Resolution:** The read-only assertion was rerun with a single-quoted Python program and simple string concatenation. The API assertion then passed without code changes.

### All initial Rego tests were undefined

**Symptom:** OPA loaded the policy bundle, but all five tests failed where they imported and called `evaluate`.

**Cause:** The public policy rule was named `decision` while the test and planned API contract used `evaluate`.

**Resolution:** The public rule was standardized as `data.athena.authorization.evaluate`. All five tests then passed without rule-logic changes.

### OPA was unreachable through its published Docker port

**Symptom:** The OPA container started, but `http://localhost:8181/health` remained unreachable.

**Cause:** OPA bound to `localhost:8181` inside its container, so Docker's port mapping could not reach the listener.

**Resolution:** Compose now starts OPA with `--addr=0.0.0.0:8181`. The recreated service passed its health check and live policy requests.

### Evaluation evidence required stable entitlement identities

**Issue:** Provenance rematerialization originally deleted and recreated effective entitlement rows. Immutable evaluations could not safely reference records that disappear.

**Resolution:** Effective entitlements now keep stable identity/grant keys and transition between active and inactive states. Rematerialization rebuilds current provenance edges while preserving the entitlement ID and all historical evaluation evidence.

### OPA treated fixture JSON files as conflicting bundle data

**Symptom:** `opa test /policies` reported merge errors for three fixture files even though the Python gate passed.

**Cause:** OPA loads JSON beneath a policy directory as data documents. The fixtures intentionally share top-level fields such as `id`, `input`, and `expected`, which conflict when merged into one OPA data tree.

**Resolution:** OPA now loads and tests only the executable `policies/iam` and `policies/system` paths. Athena's gate reads `policies/fixtures` independently. This cleanly separates policy/data bundles from test scenario documents.

### PowerShell continued after a failed native OPA command

**Symptom:** An early combined local check returned an overall success status even though OPA had printed merge errors, because later commands succeeded.

**Resolution:** The final local CI-equivalent validation checks `$LASTEXITCODE` after every native command and exits immediately on failure. GitHub Actions uses Bash's step failure behavior, where a failing command also fails the step.

### Applied risk migration needed unpublished constraint refinement

**Issue:** Migration `20260816_04` had already been exercised against the local database when explicit 0–100 score constraints were added. Because the migration was not yet published, the file and live schema temporarily differed.

**Resolution:** Only the disposable migration-04 risk tables were rolled back. The corrected migration was reapplied, Alice's authoritative baseline was restored from Keycloak, and the drift scenario was rerun. Identities, provenance grants, policy evidence, and audit history from earlier migrations were preserved. Alembic then reported zero drift.

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

### Authorization provenance

- Ruff linting: passed
- Automated tests: 18 passed
- Two-migration offline SQL generation: passed
- Live migration `20260816_02`: applied
- Alembic model/schema drift check: no new upgrade operations
- Scenario first run: 3 grants created and 3 entitlements materialized
- Scenario second run: 0 grants created and 3 entitlements materialized
- Stable provenance state: 3 grants, 3 entitlements, 8 ordered edges, 1 audit event
- Live API: Production Database Read reported `ungoverned`
- Reported gaps: `missing_business_reason`, `missing_expiration`
- Production path: `direct_grant` → `applies_to`
- Governed role path: `assigned_role` → `grants` → `applies_to`
- ORM audit-event update attempt: blocked
- Direct PostgreSQL audit-event update attempt: blocked by trigger

### Deterministic policy enforcement

- Ruff linting: passed
- Automated Python tests: 23 passed
- Rego policy tests: 5 passed
- Three-migration offline SQL generation: passed
- Live migration `20260816_03`: applied
- Alembic model/schema drift check: no new upgrade operations
- OPA health endpoint: passed after explicit container binding
- Live Alice evaluation: 2 pass, 1 fail, 0 errors
- Failed entitlement violations: `PRIVILEGED_MFA_REQUIRED`, `UNGOVERNED_PRIVILEGED_ACCESS`
- Persisted policy version: `cc7b9472d6e689bf56f2084ab142672af3c747a998bfcb0f3bd93a95058ba466`
- Provenance rematerialization preserved all 3 evaluation records
- Evaluation API returned the stored decision, input, version, and violations
- ORM evaluation mutation attempt: blocked
- Direct PostgreSQL evaluation mutation attempt: blocked by trigger
- Docker Compose validation: passed

### CI security gate and continuous controls

- Automated Python tests: 25 passed
- Rego policy tests: 5 passed
- Deterministic fixtures: 4 passed, 0 failed
- Required denial fixtures: 3 correctly denied
- NIST mappings: 3 valid, 0 failed
- AC-2 automated evidence references: 3
- AC-5 automated evidence references: 2
- AC-6 automated evidence references: 4
- JSON control and fixture parsing: passed
- GitHub Actions YAML parsing: passed
- Docker Compose validation: passed
- Alembic model/schema drift check: no new upgrade operations
- Generated JSON and Markdown evidence reports: passed
- Unsafe allow-all regression test: gate failed 3 denial fixtures as required
- Hosted GitHub Actions run `31977841305`: success

### Identity drift and access decay

- Ruff linting: passed
- Automated Python tests: 29 passed
- Four-migration offline SQL generation: passed
- Live migration `20260816_04`: applied
- Alembic model/schema drift check: no new upgrade operations
- First transfer run: 1 transition and 3 observations created
- Second transfer run: 0 transitions and 0 observations created
- Retained active entitlements after transfer: 3
- Peer group: Security department, 1 peer, Charlie
- Peer-deviating entitlements: 3
- High-risk entitlements: 1
- Alice overall score: 100/100, `critical`
- Production factor values: all seven factors at 1.0
- Risk model version: `access-decay-v1`
- Risk API factor assertion: passed
- ORM assessment mutation attempt: blocked
- Direct PostgreSQL assessment mutation attempt: blocked by trigger
- Direct PostgreSQL role-transition mutation attempt: blocked by trigger
- CI-equivalent security gate after AC-2/AC-6 updates: passed

## Current local environment

- Repository: `C:\Users\samue\Athena`
- Branch: `main`
- Remote: `origin` over HTTPS
- Python environment: `.venv`
- Docker Desktop: installed and started during Milestone 1 validation
- Keycloak: started through Docker Compose on port `8080`
- PostgreSQL: started through Docker Compose on port `5432`, migration `20260816_05` applied
- OPA: started through Docker Compose on port `8181`

Local runtime state is not source-controlled and may differ between development sessions. Use commands such as `git status`, `docker compose ps`, and the automated test suite to confirm current state rather than relying only on this snapshot.

## Milestone 5: interpretable peer anomaly analytics

Delivered an advisory machine-learning layer without transferring decision authority away from
OPA or the deterministic risk engine:

- deterministic 100-person synthetic Security cohort using seed `20260816`;
- seven versioned access-behavior features with no protected personal characteristics;
- scikit-learn 1.9 Isolation Forest with 200 trees and 5% contamination;
- immutable model-run and per-subject result evidence in migration `20260816_05`;
- SHA-256 training-cohort fingerprint and native model scores for reproducibility;
- top-three absolute feature deviations from cohort means for interpretation;
- CLI command `python -m athena.cli run-peer-anomaly --username alice`;
- API endpoint `GET /v1/identities/{identity_id}/anomaly-assessments`; and
- AC-6 automated evidence and explicit operational limitations.

### Validation evidence

- Ruff linting: passed
- Automated Python tests: 32 passed
- Rego policy tests: 5 passed
- Deterministic security fixtures: 4 passed, 0 failed
- NIST control mappings: 3 valid, 0 failed
- Live migration `20260816_05`: applied
- Alembic model/schema drift check: no new upgrade operations
- Synthetic training sample size: 100
- Persisted results per run: 101 (100 peers plus Alice)
- Training fingerprint: `4e6de0760f2a808c59f2a15c00c5d19632b67ae8d782cd16815ccea396a9c59b`
- Two live Alice runs had identical fingerprint and decision score
- Alice decision score: `-0.015415065023722807`, anomalous in both runs
- Synthetic peer anomalies: 5 of 100, matching the configured contamination baseline
- ORM anomaly-result mutation attempt: blocked
- Direct PostgreSQL anomaly-result mutation attempt: blocked by trigger
- Known upstream warning: Starlette TestClient still recommends migration from `httpx` to `httpx2`

### Failure and resolution

The first test run rejected initial model evidence creation because the parent model run was
flushed before its result relationship was populated. SQLAlchemy marked the relationship as dirty,
and the strict immutability listener blocked the apparent update. The evidence graph is now built
in memory and committed atomically in one flush, preserving append-only semantics.

During validation, a repository-wide formatter invocation also touched existing files outside the
milestone. Those whitespace-only diffs were identified and reversed before publication; only the
scoped anomaly changes remain.

## Next work: governed cohort calibration

The next slice should replace or calibrate the synthetic baseline with governed telemetry, enforce
minimum cohort sizes and fallback cohorts, measure false-positive rates, document model lifecycle
and approval controls, and add drift monitoring. Anomaly output must remain advisory.

## Journal update checklist

At the end of each meaningful change:

- update the current milestone and roadmap status;
- record delivered behavior and relevant commit identifiers;
- document architectural decisions and why they were made;
- record meaningful failures, root causes, and resolutions;
- add exact validation evidence;
- list known warnings or incomplete checks; and
- define the next smallest end-to-end outcome.
