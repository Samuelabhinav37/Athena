# Athena project journal

This document is Athena's living engineering record. Update it whenever a milestone changes the architecture, introduces a decision, encounters a meaningful problem, or produces new validation evidence.

Last updated: August 18, 2026

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

**Active milestone:** Microsoft Azure identity and authorization replacement

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
- Governed Isolation Forest peer analytics
- Human remediation review workflow
- Durable continuous monitoring
- Incremental GitHub authorization connector
- Incremental Microsoft Entra ID and Azure RBAC connector
- Keycloak OIDC authentication and role-based API authorization
- Authorized remediation execution framework
- Guarded local Ollama evidence explanations
- Authenticated React identity-governance dashboard
- Derived Neo4j identity attack-path foundation
- Authenticated attack-path dashboard presentation
- Machine and workload identity posture foundation
- Authenticated machine identity posture dashboard
- Azure service-principal owner and credential-expiration evidence

**Next outcome:** Merge the completed human review workflow presentation, then add frontend
component and accessibility testing after explicit dependency approval.

## Roadmap

| Milestone | Outcome | Status |
|---|---|---|
| 0. Repository foundation | Reproducible project structure, standards, and documentation | Complete |
| 1. Controlled identity lab | Version-controlled Keycloak realm with known ground truth | Complete |
| 2. Identity backbone | Canonical schemas, PostgreSQL persistence, migrations, and ingestion | Complete |
| 3. Authorization provenance | Trace every effective entitlement to its source | Complete |
| 4. Deterministic security | OPA policies, tests, CI security gate, and NIST mappings | Complete |
| 5. Risk analytics | Identity drift, peer analysis, and explainable access decay | Complete |
| 6. Explain and present | Ollama explanations, React dashboard, and evidence report | Complete |
| 7. Remediation and monitoring | Human decisions and durable scheduled evidence | Complete |
| 8. GitHub connector | Incremental organization authorization evidence | Complete |
| 9. Azure connector | Incremental Entra identity and Azure RBAC evidence | Complete |
| 10. API access control | OIDC authentication and role-based authorization | Complete |
| 11. Authorized execution | Approved remediation execution and verification evidence | Complete |
| 12. React dashboard | Authenticated identity, risk, review, and audit interface | Complete |
| 13. Deployment hardening | Containers, operations, backup, recovery, and demo packaging | Complete |
| 14. Attack-path analysis | Derived Neo4j projection and bounded advisory path queries | Complete |
| 15. Attack-path presentation | Authenticated dashboard graph paths and failure isolation | Complete |
| 16. Machine identity governance | Owner, usage, credential, and access posture | Complete |
| 17. Machine identity presentation | Searchable posture inventory and evidence detail console | Complete |
| 18. Azure workload lifecycle evidence | Owner and credential-expiration posture | Complete |
| 20. Azure replacement | Remove AWS runtime and make Azure the cloud authorization source | Complete |

## Milestone 20: Microsoft Azure replacement

Replaced Athena's AWS runtime integration with Microsoft Entra ID and Azure RBAC:

- stable `azure-identity` authentication through `DefaultAzureCredential`;
- separately scoped Microsoft Graph and Azure Resource Manager tokens;
- users, groups, memberships, applications, service principals, and managed identities;
- role assignments, definitions, actions, scopes, and assignment conditions;
- owner and credential-expiration evidence without key identifiers or secret material;
- trusted-origin pagination, deterministic fingerprints, removed-assignment detection, and audit
  evidence; and
- `sync-azure` plus optional continuous-monitoring integration.

The former AWS collector, synchronization service, tests, dependency, configuration, CLI command,
and operating guide were removed. Historical AWS milestones below remain only as a record of earlier
development and are not current Athena capabilities.

## Milestone 17: Machine identity dashboard presentation

Added an authenticated, cloud-console-inspired machine identity workspace to the React dashboard:

- summary cards expose identity totals, high-severity findings, missing owners, and privileged access;
- search and deterministic type/finding filters make the inventory easier to navigate;
- the resource table and detail panel expose ownership, lifecycle use, entitlements, and findings; and
- the interface labels all posture as read-only evidence and never initiates an access change.

Validation covered the TypeScript compiler, production Vite bundle, Python tests, Rego policy tests,
and Athena security gate. Visual browser inspection was unavailable because the in-app browser had
no active browser instance, so responsive behavior was verified through the compiled layout rules
and production build rather than a rendered browser session.

## Milestone 14: Neo4j attack-path foundation

Added a one-way analytical graph boundary while retaining PostgreSQL as Athena's authoritative
evidence store:

- official Neo4j Python driver `>=6.2,<7` and pinned Community image
  `neo4j:2026.06.0-community`;
- explicit, disabled-by-default graph configuration with secret-backed authentication;
- idempotent projection of active canonical provenance nodes and edges using stable UUIDs;
- bounded shortest-first privileged-resource queries with maximum depth 8 and result limit 100;
- viewer-protected `GET /v1/attack-paths/identities/{identity_id}` API;
- explicit `project-attack-graph` operator command; and
- architecture and operations guidance that prevents graph results from influencing OPA,
  remediation decisions, or execution.

### Controlled live validation

The first start attempt found Docker Desktop stopped and performed no projection. After the engine
was restarted, the pinned Neo4j service became healthy and the API image rebuilt with driver 6.2.0.
The approved projection produced eight unique nodes and eight unique lineage edges from the existing
demo evidence. Alice's bounded query returned one privileged path with relationships
`direct_grant -> applies_to`. PostgreSQL was not migrated or modified, and no access or remediation
action was executed.

## Milestone 15: attack-path dashboard presentation

Extended the authenticated identity evidence view with:

- a bounded request for up to 25 paths within six hops;
- compact node-and-relationship path rendering using the existing dependency-free design system;
- explicit `Neo4j - derived index` and `Advisory only` labels;
- loading and no-path states; and
- isolated graph failure handling that keeps PostgreSQL entitlement, risk, anomaly, and explanation
  evidence available when Neo4j is disabled or unreachable.

No frontend dependency was added. Browser-based visual inspection could not run because no in-app or
extension browser was available in the session; TypeScript compilation, the Vite production build,
static UI contract tests, and container health checks remain the required validation evidence for
this slice.

## Milestone 16: machine identity posture foundation

Added deterministic, read-only lifecycle posture for service accounts, applications, workloads, API
clients, and agents:

- viewer-protected, bounded `GET /v1/machine-identities` inventory;
- accountable owner, active/privileged entitlement counts, and latest-use summary;
- explicit findings for missing ownership, missing or stale usage, stale active credentials, and
  ungoverned entitlements;
- exclusion of humans and raw source metadata, trust policies, tokens, key identifiers, and secrets;
  and
- operating guidance that keeps posture advisory and destructive responses human-controlled.

The slice reuses canonical identities, access observations, grants, and entitlements. It introduces
no dependency or schema migration and performs no database or connector write.

Validation evidence:

- focused posture and API tests: 3 passed;
- full Python suite: 83 passed with the existing Starlette deprecation warning;
- Ruff linting: passed;
- Rego policy tests: 5/5 passed;
- deterministic security gate: four fixtures and three control mappings passed; and
- development and demo Compose configuration plus diff checks: passed.

## Milestone 18: Azure workload lifecycle evidence

The Azure replacement supersedes the former AWS role-lifecycle slice. Athena now normalizes Entra
service-principal owners and credential expiration timestamps into bounded machine-identity metadata.
Raw credentials, key identifiers, certificates, and tokens remain excluded from the posture API.
This evidence does not perform an Azure or Athena access change.

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
- Hosted GitHub Actions run `31980019943`: success
- Implementation commit: `c70d369`
- Known upstream warning: Starlette TestClient still recommends migration from `httpx` to `httpx2`

### Failure and resolution

The first test run rejected initial model evidence creation because the parent model run was
flushed before its result relationship was populated. SQLAlchemy marked the relationship as dirty,
and the strict immutability listener blocked the apparent update. The evidence graph is now built
in memory and committed atomically in one flush, preserving append-only semantics.

During validation, a repository-wide formatter invocation also touched existing files outside the
milestone. Those whitespace-only diffs were identified and reversed before publication; only the
scoped anomaly changes remain.

## Milestone 6: human remediation workflow

Delivered the first safe remediation loop:

- evidence-backed review cases sourced from the latest deterministic risk and anomaly results;
- idempotent opening of active identity reviews;
- explicit ownership, due dates, and `open → in_review → resolved` transitions;
- human decisions for `retain`, `revoke`, `extend`, and `exception`;
- append-only event history containing actor, reason, evidence snapshot, and execution state;
- assigned-owner enforcement for final decisions;
- REST endpoints under `/v1/reviews` and matching operational CLI commands;
- PostgreSQL and ORM protection against review-event updates or deletion; and
- a hard safety boundary: destructive approvals remain `pending` and do not alter entitlements.

### Validation evidence

- Ruff linting: passed
- Automated Python tests: 36 passed
- Rego policy tests: 5 passed
- Deterministic security fixtures: 4 passed, 0 failed
- NIST control mappings: 3 valid, 0 failed
- Live migration `20260816_06`: applied
- Alembic model/schema drift check: no new upgrade operations
- Live Alice workflow: `open → in_review → resolved`
- Human reviewer: Charlie
- Resolution: `revoke`
- Execution status: `pending`
- Alice active entitlements after approval: 3 of 3
- Review events recorded: 3
- ORM review-event mutation attempt: blocked
- Direct PostgreSQL review-event update and delete attempts: blocked by trigger
- Hosted GitHub Actions run `31988655931`: success
- Implementation commit: `b99d32e`
- Known upstream warning: Starlette TestClient recommends migration from `httpx` to `httpx2`

### Failure and resolution

The first shell-level immutability probe correctly failed when PostgreSQL rejected the deliberate
event update, but the command surfaced that expected database error as an overall failed check. The
follow-up probe explicitly treated rejection as success and separately verified case state and
unchanged entitlements.

### Known limitation

Version 0.1 accepts actor and owner identifiers from trusted API/CLI callers because Athena login
and role-based API authorization are not implemented yet. Production use requires OIDC-authenticated
actors, authorization policy, and separation-of-duties checks before decisions are accepted.

## Milestone 7: governed cohort calibration

Upgraded the advisory model to `peer-isolation-forest-v2` with governed cohort policy
`governed-cohort-v1`:

- consumes the latest deterministic risk features for real assessed peers;
- excludes the evaluated identity from training;
- selects department-and-role, department, then organization cohorts;
- requires at least 20 eligible identities before using a real cohort;
- falls back to the deterministic synthetic Security cohort with an explicit reason;
- records candidate counts, hierarchy, selected source, and policy version;
- distinguishes peer alert rate from reviewed false-positive rate;
- labels human `retain` and `exception` outcomes as false positives for calibration;
- records feature means and normalized feature drift against the prior comparable run;
- flags drift when maximum feature shift reaches 0.25; and
- preserves all calibration evidence inside the existing immutable model-run record.

### Validation evidence

- Focused calibration tests: 6 passed
- Full automated Python suite: 39 passed
- Ruff linting: passed
- Rego policy tests: 5 passed
- Deterministic security fixtures: 4 passed, 0 failed
- NIST control mappings: 3 valid, 0 failed
- Real cohort path at configured test threshold: passed with Charlie selected
- Minimum-size fallback path: passed
- Human-labeled false-positive calculation: passed
- Stable-distribution comparison: passed with maximum shift 0.0
- Shifted-distribution detection: passed above the 0.25 threshold
- Live cohort source: `synthetic_security`
- Live fallback reason: fewer than 20 governed assessed peers
- Live candidate counts: 0 department-and-role, 0 department, 0 organization
- Live model runs: 2 with identical fingerprint and decision score
- Live peer alert rate: 0.05, explicitly not represented as a false-positive rate
- Live reviewed anomalies: 1
- Live reviewed false-positive labels: 0, rate 0.0
- Live second-run drift status: stable, maximum feature shift 0.0
- Alembic model/schema drift check: no new upgrade operations
- Hosted GitHub Actions run `31991040762`: success
- Implementation commit: `4f3a944`

No migration was needed: cohort and calibration evidence fits the already immutable, versioned
`peer_definition` and `summary` JSON contracts introduced in migration `20260816_05`.

## Milestone 8: scheduled continuous monitoring

Delivered a durable, observable monitoring pipeline:

- PostgreSQL-backed monitoring runs keyed by a unique scheduler slot;
- ordered sync, provenance, policy, risk, anomaly, and review stages;
- immutable per-step inputs/outputs, timestamps, attempt number, status, and error evidence;
- completed-slot idempotency with no repeated external or analytical work;
- failed-slot preservation and retry on the same run with an incremented attempt;
- concurrent schedule-key claim protection through a database uniqueness constraint;
- local fixed-interval `monitor-loop` and orchestrator-friendly `monitor-once` commands;
- run history at `GET /v1/monitoring/runs`; and
- migration `20260816_07` with a PostgreSQL step-immutability trigger.

### Validation evidence

- Focused monitoring/schema tests: 5 passed
- Full automated Python suite: 43 passed
- Ruff linting: passed
- Rego policy tests: 5 passed
- Deterministic security fixtures: 4 passed, 0 failed
- NIST control mappings: 3 valid, 0 failed
- Live migration `20260816_07`: applied
- Alembic model/schema drift check: no new upgrade operations
- Live schedule key: `manual:milestone8-live`
- Live run: `f1ba3acb-5d65-41ab-b265-0750220a1960`
- First live execution: completed 6 of 6 ordered stages
- Exact schedule-key replay: idempotent, attempt remained 1, no new steps
- Identity sync: 6 updated identities, 6 groups, 8 roles
- Provenance: 3 active entitlements
- Policy evaluation: 2 pass, 1 fail, 0 errors
- Deterministic risk: 100/100 critical, 3 findings
- Peer anomaly: anomalous, synthetic fallback, no drift
- Review: one open evidence-backed case
- Live monitoring API: 200, one run, six ordered steps
- ORM monitoring-step mutation attempt: blocked
- Valid direct PostgreSQL monitoring-step update: blocked by trigger
- Hosted GitHub Actions run `31992137329`: success
- Implementation commit: `bdabaff`

### Failure and resolution

The retry test initially found that a newly persisted step was absent from the already-loaded ORM
relationship cache, which could under-report the immediate CLI step count. New steps are now attached
through the run relationship, keeping persisted and returned state consistent.

The first live SQL tamper probe had malformed JSON quoting and failed before reaching the trigger.
It was not counted as evidence. A valid update against the text error column was then rejected by
the monitoring-step immutability trigger.

## Milestone 9: GitHub authorization connector

Delivered Athena's first authorization connector after Keycloak:

- read-only, versioned GitHub REST requests with bearer-token authentication;
- organization member, team, team-member, repository, and calculated permission collection;
- pagination support at the documented 100-item page size;
- per-endpoint ETag reuse with cached payloads for `304 Not Modified` responses;
- canonical GitHub identities, organization/team groups, repository resources, permissions, grants,
  entitlements, and provenance;
- stable GitHub numeric IDs as external identifiers;
- privileged classification for repository `admin` and `maintain` roles;
- revocation and entitlement deactivation when permissions disappear;
- connector checkpoints containing endpoint cache, observation time, and content fingerprint;
- unchanged-snapshot detection that performs zero grant writes;
- optional GitHub synchronization inside continuous monitoring when configured;
- `sync-github` CLI command and sanitized `GET /v1/connectors` status API; and
- migration `20260816_08` for checkpoint storage and grant source metadata.

### Provenance decision

GitHub's calculated-permission endpoint returns the highest effective repository role across direct,
team, organization, and enterprise sources, but not the exact contributing lineage. Athena records
`reported_effective_permission`, `lineage_complete=false`, and the limitation text rather than
misrepresenting the result as a direct grant.

### Validation evidence

- Focused connector/schema tests: 5 passed
- Full automated Python suite: 47 passed
- Ruff linting: passed
- Rego policy tests: 5 passed
- Deterministic security fixtures: 4 passed, 0 failed
- NIST control mappings: 3 valid, 0 failed
- Collector authorization and API-version headers: passed
- Organization team membership normalization: passed
- Endpoint ETag/304 cached-payload reuse: passed
- Multi-page endpoints are fully refetched so a first-page ETag cannot hide later-page changes
- Canonical permission ingestion and provenance: passed
- Missing-permission revocation and entitlement deactivation: passed
- Connector status API omits cached payload content: passed
- Live migration `20260816_08`: applied
- Alembic model/schema drift check: no new upgrade operations
- First live deterministic snapshot: 1 identity, 1 private repository, 1 admin permission,
  1 privileged grant and entitlement
- Identical second snapshot: unchanged, zero grant writes
- Live provenance relationship: `reported_effective_permission`
- Live governance state: ungoverned because upstream approval and justification are unavailable
- Hosted GitHub Actions run `31993327141`: success
- Implementation commit: `fe8a051`

### Known limitations

- No production GitHub token was supplied, so external collection was verified with deterministic
  HTTP mocks rather than the user's organization.
- The effective-permission endpoint scales with member × repository combinations; larger
  organizations will need GraphQL batching, audit-log enrichment, or another optimized strategy.
- Fine-grained source lineage remains incomplete until team/repository grant sources are correlated.

## Documentation refresh: portfolio-style project README

Redesigned the root README to make Athena easier to understand, evaluate, and run:

- added a concise project identity, security-gate and technology badges, and quick navigation;
- introduced the five authorization questions and a concrete role-transition business scenario;
- added a Mermaid architecture diagram showing collection, normalization, evaluation, governance,
  remediation, evidence, and monitoring;
- summarized delivered capabilities, authorization provenance, and API evidence in compact tables;
- added copy-ready quick-start, end-to-end demo, and GitHub connector instructions;
- documented the repository map and separated completed work from planned roadmap items; and
- linked the architecture, journal, branch-protection, Keycloak, contribution, security, and license
  documentation.

The presentation structure was inspired by the public AI Red-Teaming Lab portfolio README while
retaining Athena's own architecture, terminology, evidence, and commands. The in-app browser was
unavailable during inspection, so the public GitHub page was reviewed through direct web access.
No application behavior changed.

### Validation evidence

- Markdown whitespace validation (`git diff --check`): passed
- All local README documentation and workflow link targets: present
- Delivered and planned capabilities are visibly separated
- README redesign commit: `5f1d0f4`
- Hosted GitHub Actions run `31996341828`: success

## Retired milestone 10: former AWS IAM authorization connector

Delivered Athena's first cloud authorization connector:

- standard boto3 credential-chain support with optional profile and region configuration;
- read-only account discovery through STS and IAM authorization inventory;
- pagination for account authorization details and per-user access-key metadata;
- canonical IAM user and role identities plus group memberships;
- role trust-policy and permissions-boundary metadata;
- customer-managed, AWS-managed, and inline policy collection;
- normalization of Allow actions and AWS resource ARN patterns into grants and permissions;
- direct-user, group-inherited, and role-identity provenance;
- access-key status, creation time, and calculated age without secret key material;
- stable content fingerprints, unchanged-snapshot detection, missing-grant revocation, and missing
  identity deactivation scoped to the AWS account;
- sanitized connector checkpoints and append-only synchronization audit events;
- `sync-aws-iam` CLI integration and optional continuous-monitoring integration; and
- a least-privilege collector policy and operating guide in `docs/aws-iam.md`.

### Authorization decision

Policy inventory is not represented as definitive AWS effective access. Every policy-derived grant
records `lineage_complete=false` and identifies the unresolved influence of explicit Deny,
permissions boundaries, service-control policies, resource and session policies, conditions, and
indirect role assumption. This preserves useful evidence without overstating Athena's current AWS
authorization evaluator.

No database migration was required because the canonical identity, group, cloud resource,
permission, grant, provenance, audit-event, and connector-checkpoint models already cover this
connector.

### Validation evidence

- Focused AWS collector and synchronization tests: 2 passed
- Full automated Python suite: 49 passed
- Ruff linting: passed
- boto3 package/import validation: `1.43.72`
- AWS authorization and access-key pagination: passed with deterministic clients
- IAM users, roles, groups, policies, trust metadata, and access-key age normalization: passed
- Direct and group-inherited provenance materialization: passed
- Explicit Deny statements are not materialized as Allow grants: passed
- Unchanged snapshot: zero grant writes
- Missing policy access revocation and entitlement deactivation: passed
- Docker Compose configuration validation: passed
- Implementation commit: `556d074`
- Hosted security-gate badge for `main`: passing; GitHub's Actions REST endpoint returned repeated
  `504 Gateway Time-out` responses, so the exact hosted run identifier could not be retrieved

### Errors and resolutions

The first lint run found import ordering, one unused import, and two overlong lines. Imports and line
wrapping were corrected before the full suite. The system Python did not contain the project test
dependencies, so validation was rerun through the repository's `.venv`. A combined infrastructure
check later stalled because Docker Desktop was not running; the process was terminated, Compose
syntax was verified independently, and service-backed migration, Rego, and security-gate checks
were deferred to hosted GitHub Actions.

### Known limitations

- No AWS credentials or account were supplied, so external collection was verified with deterministic
  IAM and STS clients rather than a production account.
- The connector inventories policy evidence but does not yet implement full AWS authorization
  simulation, explicit-Deny evaluation, Organizations SCPs, or indirect role-assumption resolution.
- Policy variables, `NotAction`, `NotResource`, and runtime condition context require a later AWS
  evaluation engine.

## Milestone 11: OIDC authentication and API authorization

Delivered Athena's API security boundary:

- Keycloak JWKS signature verification with cached signing-key discovery;
- a fixed `RS256` algorithm allow-list rather than trusting the token header;
- issuer, `athena-api` audience, expiration, issued-at, subject, and required-claim validation;
- consistent `401` responses with `WWW-Authenticate: Bearer` for invalid authentication;
- hierarchical viewer, analyst, reviewer, and administrator authorization with explicit `403`
  responses;
- authentication on every `/v1` route while health and readiness remain public;
- viewer access to identity, authorization, risk, review, connector, and monitoring evidence;
- analyst permission to open reviews and reviewer permission to assign and decide them;
- authenticated review actors derived from the validated username instead of request JSON;
- `GET /v1/auth/me` for the validated subject, username, and role set;
- version-controlled composite Keycloak roles and an `athena-api` access-token audience mapper;
- Acme Corp role assignments for viewer, analyst, reviewer, and administrator demonstrations; and
- a dedicated authentication and role-matrix guide.

### Security decisions

Athena validates tokens locally instead of calling Keycloak on every request. The verifier pins the
allowed signing algorithm, requires the configured issuer and audience, and refreshes signing keys
through JWKS. Realm and `athena-api` client roles are accepted, but application authorization uses a
single explicit hierarchy.

Review request schemas no longer accept `actor`. The authenticated `preferred_username` becomes the
append-only review-event actor, and only that authenticated username can decide a case assigned to
it. This closes the prior caller-impersonation path.

No migration was required because existing review events already preserve actor identity. The API
contract intentionally changed before external clients exist.

### Validation evidence

- Focused authentication, Keycloak realm, and risk API tests: 21 passed
- Full automated Python suite: 56 passed
- Ruff linting: passed
- Docker Compose configuration validation: passed
- Valid RS256 signature, issuer, audience, identity, and role extraction: passed
- Wrong audience, wrong issuer, and expired-token rejection: passed
- Missing bearer credentials return `401` with a Bearer challenge: passed
- Higher-role inheritance and insufficient-role `403` behavior: passed
- Composite realm roles and `athena-api` audience mapper structure: passed
- Authenticated Charlie owns open, assignment, and decision review events: passed
- Markdown whitespace validation: passed
- Implementation commit: `58e5e71`
- Hosted GitHub Actions run `32050846744`: success

### Errors and resolutions

The first review API regression returned `409` because the authenticated-principal override had
been inserted into an unrelated risk endpoint test. The override was moved to the review workflow,
which then proved that the assigned owner and authenticated decision actor are the same. An initial
lint command also included the JSON realm file as Python input; validation was rerun against Python
sources while realm correctness remained covered by JSON parsing and structural tests.

### Known limitations

- Docker Desktop remains stopped, so a live Keycloak login and key-rotation exercise could not run
  locally; deterministic RSA tokens and hosted CI cover the verifier and realm structure.
- The React authorization-code-with-PKCE login flow is not implemented yet.
- Token revocation takes effect at access-token expiry unless a future denylist or introspection mode
  is enabled.
- `ATHENA_AUTH_REQUIRED=false` is available only for isolated development and tests; production must
  keep authentication enabled.

## Milestone 12: authorized remediation execution framework

Delivered the durable safety boundary between a review decision and an upstream access change:

- administrator-only execution creation and evidence APIs;
- execution requests accepted only from resolved `revoke` decisions with an active entitlement;
- one execution per review plus globally unique caller-supplied idempotency keys;
- immutable before evidence linked to the review decision event and normalized target;
- source-specific adapter protocol with separate revoke and verify operations;
- exact adapter/grant source matching and stable idempotency keys on retry;
- pending, running, succeeded, failed, and verification-failed states;
- retryable failure evidence with attempt counts and append-only transitions;
- generic persistence for unexpected adapter errors so upstream secrets cannot leak into evidence;
- local grant revocation and provenance rematerialization only after verification succeeds;
- no-op replay after success and active-access preservation on every failure path;
- SQLAlchemy immutability guards plus a PostgreSQL trigger for execution events;
- migration `20260817_09`; and
- an execution architecture, status, API, adapter, and safety-invariant guide.

### Credential-boundary decision

The API can authorize and store an execution request but exposes no run endpoint and holds no
connector write credentials. A separate worker must inject an adapter. A connector receipt is not
treated as success: its independent verification method must prove upstream removal before Athena
revokes the canonical grant.

The first framework supports `revoke` only. `extend` lacks a reviewed target expiration and remains
outside execution until its decision contract captures that value explicitly.

### Validation evidence

- Focused execution safety and administrator API tests: 5 passed
- Full automated Python suite: 61 passed
- Ruff linting: passed
- Docker Compose configuration validation: passed
- Unapproved, unresolved, missing-entitlement, and inactive-access rejection: passed
- Execution request and idempotency-key replay: passed
- Adapter source binding and stable retry key: passed
- Verified success, local revocation, and provenance deactivation: passed
- Execution failure and verification failure preserve active access: passed
- Successful execution replay performs zero additional adapter calls: passed
- Authenticated administrator recorded as execution requester: passed
- Viewer execution creation denied with `403`: passed
- ORM execution-event immutability: passed
- Implementation commit: `a863b7b`
- Hosted GitHub Actions run `32052988721`: success

### Errors and resolutions

The first deterministic fixture omitted Bob, whom the established provenance scenario requires; the
fixture was aligned with the controlled identity lab. The first verified run left its entitlement
active because the session disables autoflush and provenance queried before seeing the in-memory
grant revocation. An explicit flush was added before rematerialization. The canonical schema contract
then correctly failed on the two new tables and was updated to include them.

### Known limitations

- Production GitHub and Azure write adapters are intentionally not implemented or enabled.
- A separate worker process, credential delivery mechanism, leasing, and crash recovery are still
  required before production execution.
- Live PostgreSQL trigger and migration validation depend on hosted CI while Docker Desktop is
  stopped locally.
- `extend` and connector-specific rollback or compensation flows are not yet modeled.

## React dashboard

Added the `apps/web` React, TypeScript, and Vite application with exact dependency versions locked
in `package-lock.json`. The dashboard uses Keycloak authorization code with PKCE S256, stores the
OIDC user in session storage, keeps tokens in authorization headers, and uses a same-origin Vite
proxy for the protected API instead of enabling permissive CORS.

The interface provides:

- role-aware authenticated navigation and principal context;
- an authorization posture overview with review, connector, monitoring, and execution signals;
- searchable identity inventory with entitlement governance, ordered provenance, risk, and anomaly
  evidence;
- human review queue and immutable decision context; and
- connector freshness, monitoring history, and administrator-only remediation evidence.

The UI never performs real connector actions and exposes no grant, revoke, or execution control.
Remediation remains behind Athena's separately authorized API and human approval boundary.

### Errors and resolutions

The initial TypeScript pass could not resolve Vite's `import.meta.env` and CSS module declarations.
Adding the standard `vite/client` ambient declaration fixed both errors. The first stylesheet also
requested hosted fonts; that request was removed so the dashboard makes no unnecessary third-party
network call. A local browser preview returned HTTP 200, but visual browser automation was not
available in this session, so interactive visual QA remains an explicit follow-up.

### Known limitations

- Review assignment and decision forms are not yet exposed in the UI; the current milestone is a
  safe read-oriented evidence workspace.
- The current frontend gate is TypeScript plus the production build. Component-level DOM tests will
  require a separately approved test dependency.
- Interactive PKCE login and authenticated data rendering require the local Keycloak and API stack.

### Validation evidence

- `npm install` audit: 27 packages audited, 0 known vulnerabilities
- `npm run typecheck`: passed
- `npm run build`: passed; 20 modules transformed
- Local Vite availability: HTTP 200 on `127.0.0.1:3000`
- Full automated Python suite: 61 passed, with one existing Starlette deprecation warning
- Ruff linting: passed
- Docker Compose configuration validation: passed
- Rego tests and the OPA-backed security gate: not run successfully because Docker Desktop was
  stopped and no OPA service was listening on `localhost:8181`
- Automated visual browser inspection: unavailable because no controllable browser was connected
- Implementation branch: `feature/react-dashboard`; no commit or push performed

## Next work: evidence-grounded explanations

Add a local Ollama explanation adapter that consumes immutable evidence snapshots, treats all
connector content as untrusted data, cites the evidence used, and cannot create policy decisions or
execute remediation.

## Local Ollama evidence explanations

Added a viewer-protected, read-only explanation endpoint at
`POST /v1/identities/{identity_id}/explanation`. It builds a bounded snapshot from existing identity,
entitlement, provenance, policy, risk, and anomaly records and asks a local Ollama model for a
schema-constrained summary. The response includes its model, generation time, referenced evidence
identifiers, canonical snapshot digest, findings, limitations, and a mandatory decision-boundary
disclaimer.

### Trust-boundary decisions

- Ollama URLs are restricted to loopback HTTP endpoints so normalized identity evidence cannot be
  sent to a remote inference service through this feature.
- Connector and identity strings remain untrusted data. Prompt delimiters are escaped, the system
  instruction explicitly rejects embedded commands, and the model receives no tools.
- Requests use temperature zero, non-streaming responses, and a supplied JSON Schema. Pydantic
  rejects output that does not match the response contract.
- Evidence size and record counts are bounded. The generated explanation is not persisted as an
  authoritative fact and has no path into OPA, analytics, reviews, grants, or execution.
- Unavailable or malformed model responses fail closed with `503`; Athena never fabricates a
  fallback explanation.

### Errors and resolutions

The first focused test run could not find database and API fixtures because those fixtures were
module-local in an older test file. Local in-memory fixtures were added to the new explanation test
instead of refactoring unrelated test infrastructure. Ruff then identified import ordering in the
identity route; the imports were reordered without changing behavior.

### Validation evidence

- Focused explanation security and failure tests: 4 passed
- Ruff linting: passed
- Non-local Ollama URL rejection: passed
- Prompt-delimiter injection remains escaped inside the untrusted evidence block: passed
- Schema-constrained request, zero temperature, non-streaming mode, and no model tools: passed
- Invalid structured model output fails closed: passed
- No dependency, model download, database schema, migration, or persistence change introduced

### Known limitations

- A local Ollama installation and operator-selected model are required for a live response.
- Generated explanations are intentionally ephemeral; the evidence digest allows a reviewer to
  identify the source snapshot but does not turn generated prose into authoritative audit evidence.
- Dashboard presentation of the explanation will follow after the independent dashboard branch is
  merged.

## Explain-and-present integration

Combined the authenticated dashboard and guarded explanation API into one end-to-end identity
evidence view. Viewers can explicitly request a local explanation for the selected identity. The UI
labels generated content advisory, displays its local model, evidence-reference count, and digest,
and keeps it visually separate from authoritative authorization lineage.

Added administrator-only JSON and Markdown authorization evidence reports. Reports deterministically
summarize identity, active entitlement, policy, risk, anomaly, review, execution, monitoring,
connector, and audit-event records plus version-controlled NIST control mappings. An integrity
digest covers canonical facts and limitations while excluding generation time, allowing unchanged
evidence to produce the same digest across representations.

### Security and architecture decisions

- Explanation generation remains explicit and never runs automatically while browsing identities.
- Explanation failures stay local to the advisory panel and do not hide authoritative evidence.
- Full evidence reports require the administrator role; viewers receive `403`.
- Report generation is read-only and introduces no model, migration, database write, or persisted
  report state.
- Generated LLM text is excluded from authoritative report facts and the facts digest.
- The Markdown download uses the authenticated API response and creates a short-lived browser object
  URL; access tokens never enter the download URL.

### Errors and resolutions

Merging the two independently validated feature branches produced expected conflicts in README and
project-journal milestone text. Both completed states were preserved, the combined codebase passed
frontend and backend validation, and refreshed PR checks passed before the explanation PR merged.
The first report test compared a substring directly against a list of full limitation sentences;
the assertion was corrected to express its intended prefix check. Ruff also caught one long
Markdown-table initializer, which was split without changing output.

### Validation evidence

- Dashboard explanation TypeScript check and production build: passed
- Focused report and explanation tests: 7 passed
- Full automated Python suite: 68 passed, with one existing Starlette deprecation warning
- Docker Compose configuration validation: passed
- Administrator JSON and Markdown report access: passed
- Viewer report denial with `403`: passed
- Stable evidence digest for unchanged facts: passed
- LLM output exclusion from report facts and Markdown: passed
- Ruff linting: passed
- No dependency or database migration introduced
- Dashboard PR #1 merge commit: `95c893b`
- Explanation PR #2 merge commit: `346dde1`
- Combined pull-request security gate run `32094159468`: success

### Known limitations

- Live explanation rendering still requires an operator-installed local Ollama model.
- The report is a point-in-time summary, not a signed artifact or external certification.
- Production backup, restore, retention, telemetry, and deployment runbooks remain to be defined.

## Deployment and operations hardening

Added a reproducible deployment and controlled-demonstration baseline:

- Python 3.13.14 slim API image running as dedicated UID/GID 10001;
- Node 24.14.1 build stage and NGINX 1.29.8 web runtime running as `nginx`;
- read-only web container filesystem with an ephemeral `/tmp`;
- same-origin NGINX proxy for protected `/v1/` API calls;
- complete demo Compose topology with non-published PostgreSQL and OPA services, required secret
  placeholders, persistent database storage, health checks, dependency conditions, and restart
  policies;
- production settings validation that rejects disabled authentication, development database and
  Keycloak credentials, and a non-HTTPS OIDC issuer;
- bounded JSON request events with safe correlation IDs and no query strings, headers, bodies,
  tokens, claims, or evidence content; and
- deployment, observability, backup, restore-rehearsal, retention, and recovery guidance.

### Architectural decisions

The API does not apply migrations automatically. Migration is a separately authorized operator
step because it changes the evidence store. The demo stack also does not weaken the loopback-only
Ollama boundary: explanations remain unavailable from the containerized API until a reviewed
co-located inference topology exists.

The original Uvicorn access log is disabled in the API image in favor of Athena's bounded request
event. Safe caller-provided request IDs are returned and preserved; unsafe values are replaced with
UUIDs so they cannot forge structured log lines.

### Validation evidence

- Focused deployment, production-configuration, and request-observability tests: 6 passed
- Full automated Python suite: 74 passed, with one existing Starlette deprecation warning
- Frontend TypeScript check and production build: passed
- Development and demo Compose configuration validation: passed
- Ruff linting and diff checks: passed
- Container base versions and non-root runtime declarations: covered by static regression tests
- PostgreSQL and OPA host-port non-publication plus required demo secrets: covered by regression
  tests
- No package dependency or new database migration introduced

### Known limitations

- The controlled local demo built and exercised the images; production TLS, external secret
  management, and platform-specific deployment validation remain out of scope locally.
- The Keycloak `start-dev` mode and imported Acme realm are demonstration components only.
- Backup and restore commands are documented but were not executed; every database operation still
  requires explicit approval and an isolated verified target.
- Image signing, SBOM/vulnerability enforcement, TLS ingress, external secret management, and
  production telemetry backends remain deployment-platform responsibilities.

### Controlled demo finding

The first local demo start built both images and brought PostgreSQL and OPA to healthy state, but
Keycloak remained in `health: starting`. Its HTTP/1.0 probe omitted the mandatory `Host` header;
Keycloak 26 rejected the request while serving normally. The probe now supplies `Host: localhost`,
with a regression assertion on the resolved Compose source. No migration or application service was
started before this health failure was diagnosed.

After the corrected stack became healthy, the first protected proxy request correctly returned
`401`, but the live API log did not contain the expected JSON request event. The dedicated logger had
had no output handler under Uvicorn's default logging configuration; focused tests had installed a
capture handler and masked the runtime behavior. Athena now gives the request logger a dedicated
stdout handler at INFO level, disables propagation to prevent duplicates, and tests that default
configuration explicitly.

Recreating only the API container then exposed NGINX's startup-time DNS caching: the web proxy kept
the replaced container's old address and returned `502`. The proxy now resolves the Compose service
name through Docker's embedded DNS with a short validity window, allowing routine API replacement
without requiring the web container to restart.

The same live trace showed that NGINX replaced caller-provided request IDs before they reached the
API. The proxy now forwards the original header; the API remains the trust boundary that preserves
safe values and replaces missing or unsafe values with a UUID.

With explicit operator approval, the fresh demo database was migrated through `20260817_09` and
`alembic check` reported no pending schema operations. PostgreSQL, Keycloak, OPA, API, and web all
reached healthy state; the dashboard, realm endpoint, and same-origin proxy were exercised. No
backup, restore, downgrade, deletion, identity synchronization, or monitoring-pipeline write was
performed.

### Controlled demo data phase

Before synchronization, the demo API's collector endpoint was still using its loopback default,
which would address the API container rather than Keycloak. The Compose service now supplies
`ATHENA_KEYCLOAK_URL=http://keycloak:8080`, covered by a static deployment regression assertion.

With a second explicit operator approval, the isolated demo database received the documented
non-destructive scenario data:

- Keycloak synchronization observed six groups, created six identities, and observed eleven roles;
- provenance seeding created three grants and materialized three entitlements; and
- monitoring slot `manual:controlled-demo-20260818` completed six ordered steps on attempt one.

Replaying that completed schedule key returned the same run as an idempotent no-op. `alembic check`
reported no schema operations, and all five Rego tests passed. Running the security gate directly in
the production API image initially reported missing test-evidence paths because that minimal image
does not package the repository's `tests/` directory. The CI-equivalent retry mounted only that
directory read-only into an ephemeral API container and passed all four fixtures and all three
control mappings. No GitHub/cloud collection, access execution, deletion, downgrade, backup, restore,
or remediation action was performed.

## Repository guardrails for coding agents

Added repository-scoped operating and enforcement guidance for Codex and other coding agents:

- root `AGENTS.md` defines Athena-specific scope control, destructive-action prohibitions, Git
  discipline, secret handling, prompt-injection treatment, decision-model invariants, dependency
  policy, verification requirements, stop conditions, and project context; and
- `.codex/config.toml` selects `workspace-write`, `on-request` approvals, disabled sandbox network
  access, and an optional read-only review profile.

The supplied files contained no credentials or personal secrets. They were placed at their intended
repository paths without changing their policy content.

Validation evidence:

- downloaded and repository content match after newline normalization;
- TOML parsing and expected enforcement values: passed;
- full automated Python suite: 61 passed;
- hosted GitHub Actions run `32070842912`: success; and
- implementation commit: `6b8a659`.

## Journal update checklist

At the end of each meaningful change:

- update the current milestone and roadmap status;
- record delivered behavior and relevant commit identifiers;
- document architectural decisions and why they were made;
- record meaningful failures, root causes, and resolutions;
- add exact validation evidence;
- list known warnings or incomplete checks; and
- define the next smallest end-to-end outcome.

## Vendor-neutral platform roadmap

### Objective

Evolve Athena into a portable identity-governance platform whose evidence, policy, review, and
remediation boundaries do not depend on a single AI provider, IAM vendor, log platform, or
compliance framework. Azure AI will be the first hosted demonstration adapter, while Ollama remains
the local/private adapter. Neither provider may influence deterministic policy decisions or approve
access changes.

### Architectural direction

- Define versioned contracts for AI providers, IAM connectors, log receivers/exporters, policy
  engines, compliance-framework packs, and documentation renderers.
- Preserve one canonical Athena identity and authorization graph with source provenance, collection
  freshness, capability metadata, and explicit incomplete-data warnings.
- Use open standards at integration boundaries: OIDC and SAML for federation, SCIM for identity
  provisioning, SPIFFE for workload identity, OpenTelemetry/OTLP for telemetry, and OSCAL for
  machine-readable control and assessment information.
- Keep OPA/Rego as the initial authoritative policy engine. Additional engines, such as Cedar, must
  be isolated behind adapters and conformance tests because policy semantics cannot be assumed to
  be interchangeable.
- Treat all ingested IAM records, logs, policy text, and model responses as untrusted data. Provider
  output remains advisory presentation and is excluded from authoritative evidence facts.

### Phased delivery plan

1. **Architecture and contracts** — document schemas, capability manifests, trust boundaries,
   compatibility rules, conformance tests, and threat models.
2. **AI portability** — introduce a provider-neutral `AIProvider` contract, move the existing
   Ollama explanation path behind it, and add Azure AI with bounded redacted requests, structured
   response validation, safe authentication, timeouts, safety handling, and audit metadata.
3. **AI boundary verification** — test provider switching, fallback, prompt injection, malformed
   output, secret exclusion, and the invariant that model output cannot alter OPA decisions,
   evidence facts, or remediation state.
4. **Universal telemetry** — define an OpenTelemetry-aligned security-event envelope, then add OTLP,
   syslog, JSON, and webhook receivers plus vendor-neutral exporters without losing original-event
   provenance.
5. **IAM connector SDK** — standardize discovery, pagination, cursors, retries, freshness, read-only
   behavior, and capability reporting; require every connector to declare support for inheritance,
   nested groups, deny rules, privileged eligibility, machine identities, and activity signals.
6. **Framework engine** — adopt OSCAL-compatible catalogs, mappings, implementation statements,
   evidence links, assessment results, and versioning; expand from NIST to ISO 27001, SOC 2, CIS,
   PCI DSS, HIPAA, SOX, and organization-defined controls where licensing permits.
7. **Policy interoperability** — formalize a canonical principal-action-resource-context request,
   retain OPA as the default authority, and evaluate additional engines through explicit adapters
   and semantic conformance suites rather than lossy policy translation.
8. **Portable reporting** — render the same verified evidence package as Markdown, JSON, OSCAL,
   PDF, and Word while keeping generated AI prose separate from authoritative facts.
9. **Enterprise hardening** — add tenant isolation, SSO and delegated RBAC, data-residency controls,
   high availability, disaster recovery, signed extensions, observability, scale tests, and a
   published compatibility matrix.

### First implementation milestone

The next smallest end-to-end outcome is the AI portability slice: document the provider contract,
migrate Ollama without changing behavior, add the guarded Azure AI adapter, and prove through tests
that both providers return the same Athena-owned response schema while policy and evidence results
remain unchanged. This roadmap records intent only; implementation and dependency choices require
their own reviewed change.
