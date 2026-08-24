# Tenant-isolation contract and threat model

Athena's development runtime now carries validated tenant context through its primary API,
database, connector, graph, and report paths, but the production-readiness manifest remains
`design_only`. Azure tenant IDs, GitHub organizations, Keycloak realms, connector scopes, and
identity sources remain collected evidence—not Athena tenant authority. Production startup is
blocked until every isolation and recovery gate in this contract is complete and separately
authorized.

Contract `1.0` defines the target as shared-database row isolation. A canonical lowercase Athena
tenant ID must come from a validated context bound to an approved identity issuer or internal
service identity. Every persisted business/evidence row and every scoped reference must carry that
key. There is no global-administrator bypass. `require_tenant_access` demonstrates the default-deny
comparison rule used by tenant-scoped runtime boundaries.

## Trust boundaries

- The token verifier must bind the configured issuer, audience, subject, and dedicated
  `athena_tenant_id` claim. Request headers, query parameters, routes, and connector payloads cannot
  select or override a tenant.
- Background jobs must receive a validated tenant context in their durable schedule identity; no
  ambient process default may select a tenant.
- Database sessions must set transaction-local tenant context and enforce row-level security even
  if an application query omits its filter. Connection-pool reuse must clear or replace context.
- Object stores, caches, artifact names, idempotency keys, rate limits, graph projections, telemetry,
  backups, and restore operations must include and independently authorize the tenant boundary.
- Provider tenant IDs remain provenance. An administrator explicitly maps provider scopes to one
  Athena tenant; provider data cannot create or switch platform tenants.
- `connector_scope_bindings` deliberately keeps one global `(connector, scope)` uniqueness key.
  This is a narrow authority-registry exception: it prevents one external provider scope from being
  approved for two Athena tenants. Runtime reads remain tenant-filtered and protected by RLS.

## Threats and required mitigations

| Threat | Required mitigation |
|---|---|
| Missing tenant filter or unsafe join | Non-null tenant keys, composite foreign keys, RLS, negative SQL/ORM tests |
| Forged tenant header or token claim | Ignore headers; validate claim with issuer/audience and approved membership |
| Privileged cross-tenant access | No role bypass; separately authorized support workflow with immutable evidence |
| Connection-pool context leakage | Transaction-local context, fail closed when unset, reset tests across reused connections |
| Cache, job, or idempotency collision | Tenant-prefixed keys plus tenant ownership validation on retrieval/replay |
| Connector scope confusion | Explicit tenant-to-provider-scope mapping; source IDs never confer Athena authority |
| Export, logs, or error leakage | Tenant-scoped selection and destinations; redaction; no foreign identifiers in errors |
| Graph edge crossing tenants | Tenant-partitioned projection and edge constraints; cross-tenant path fixtures |
| Backup or residency violation | Tenant-aware encryption, retention, restore authorization, and region policy |

## Migration preconditions

The `TENANT_ISOLATION_PLAN` enumerates the affected entity families and blockers. Implementation
requires a reviewed, non-destructive migration sequence: introduce nullable keys; assign every
existing row to an explicitly approved bootstrap tenant; validate referential consistency; replace
unique and foreign-key constraints with tenant-aware forms; add and test RLS; then enforce non-null
keys. No guessed backfill is permitted.

Authentication and database changes are deliberately absent from this phase. Production tenancy
must not be enabled until API, ORM, direct SQL, background jobs, exports, Neo4j projections,
connectors, caches, backup/restore, and residency controls all pass cross-tenant denial tests.

## Bootstrap transition plan

`BootstrapTenantApproval` requires an explicit tenant ID, approver, approval reference,
timezone-aware approval time, and expected row count for every one of Athena's 25 tables. Missing,
extra, negative, or changed inventory fails closed. `build_tenant_transition_plan` produces a
content-digested six-phase plan:

1. freeze writers, compare exact inventory, and confirm recoverable backup evidence;
2. add the approved bootstrap key without ORM mutation of immutable evidence;
3. replace global references and uniqueness with tenant-aware integrity constraints;
4. add fail-closed PostgreSQL row-level security and pooled-session isolation;
5. propagate validated context through APIs, jobs, connectors, caches, exports, and graph; and
6. enforce non-null keys and enable tenancy only after every isolation and recovery gate passes.

The plan is `review_required`; it is not executable migration code. Observed inventory must match
the approved counts immediately before any database mutation, preventing a stale approval from
silently assigning newly created evidence to the bootstrap tenant.

Run `python -m athena.cli tenant-inventory` to capture the approval inventory. The command checks
that its SQLAlchemy session has no pending changes, counts all 25 known tables using model metadata,
and emits a timestamp, total, per-table counts, and deterministic digest. It never returns row
content or commits a transaction. Repeating it with unchanged counts produces the same digest; any
count change invalidates the previously approved bootstrap inventory.

## First additive schema step

Migration `20260820_10` creates a global tenant registry and adds an indexed, nullable `tenant_id`
foreign key to all 25 scoped tables. The approved local bootstrap record is versioned at
`tenancy/bootstrap-approval.json` and binds tenant `athena-local` to the exact 614-row inventory
digest approved under `LOCAL-BOOTSTRAP-2026-001` by `samue`.

The migration deliberately performed no insert, update, backfill, non-null enforcement, composite
constraint replacement, RLS policy, token handling, or runtime selection. Immediately after this
schema step, existing rows remained unassigned and Athena remained single-tenant. The later
backfill required its own inventory verification, approved digest, and explicit execution approval.

## Bootstrap backfill dry-run

`python -m athena.cli tenant-backfill-plan --approval-file tenancy/bootstrap-approval.json` reads
the approved artifact, recaptures all 25 table counts, verifies the inventory digest, and checks
that the bootstrap tenant does not yet exist and every scoped row remains unassigned. It emits a
deterministic plan digest and proposed operation counts with `database_mutation: false`.

The dry-run cannot create a tenant or update a row. It produced the separately approved local plan
used by the transactional executor described below.

## Transactional bootstrap executor

`tenant-backfill` requires the approval artifact and the exact digest emitted by the dry-run. It
takes exclusive locks on the tenant registry and all 25 scoped tables before recapturing inventory,
so writers cannot invalidate approval between verification and assignment. A mismatch, an existing
bootstrap tenant, a preassigned row, or a changed plan digest aborts the transaction.

During that same transaction, existing immutable trigger functions temporarily accept only a
`tenant_id` transition from null to the transaction-local approved tenant when every other row
field is identical. Deletes, content changes, and later tenant changes remain rejected. The command
restores the original trigger bodies before verifying counts and committing; any error rolls back
the tenant record, assignments, and trigger definitions together.

After disposable PostgreSQL verification, the executor ran against the local evidence store under
explicit approval of plan digest
`c9ec5582876176fd0e4e23d43cd0f0b50805245a086c44353ae6fd040ec721a3`. It created the approved
`athena-local` tenant and assigned all 614 approved rows atomically; post-execution inventory and
immutable-trigger checks passed.

## Tenant integrity readiness

`python -m athena.cli tenant-integrity` derives its coverage from SQLAlchemy metadata and performs
no writes. It counts unassigned rows, checks each scoped foreign-key join for differing tenant
ownership, and inventories unique constraints that still have global scope. Readiness is false if
any scoped row is unassigned or any relationship crosses tenants.

On the current local database, all approved rows are assigned, all scoped relationships have zero
mismatches, and no tenant-scoped uniqueness rule remains global. This integrity result allowed the
separately approved constraint and RLS migrations; it does not by itself make the broader
production-readiness manifest `ready`.

## Tenant-aware constraint plan

`python -m athena.cli tenant-constraint-plan` derives a deterministic, non-mutating replacement
plan from the same model metadata. It covers all 15 global unique constraints, all 32 scoped foreign
keys, and the 13 supporting `(tenant_id, referenced_column)` constraints required by PostgreSQL.
Every proposed uniqueness and relationship key begins with `tenant_id`, and generated names are
deterministically bounded to PostgreSQL's 63-character identifier limit.

The approved pre-migration plan had digest
`96d2704ac77e61af959f27a8acdfcd51e8f98515dc1ee83e535cd951993550c8`. Migration
`20260823_11` applied it after the bootstrap backfill and a successful integrity report. Tenant keys
are now non-null; all 15 scoped uniqueness rules and all 32 scoped relationships include
`tenant_id`, with 13 supporting parent constraints. PostgreSQL negative testing confirms that
missing tenant assignment and cross-tenant associations fail closed.

## Row-level-security plan

`python -m athena.cli tenant-rls-plan` produces a deterministic, non-mutating plan for all 25
scoped tables. Every policy enables and forces RLS and applies the same predicate to reads and
writes: `tenant_id = nullif(current_setting('athena.tenant_id', true), '')`. Missing and empty
settings therefore match no tenant row instead of falling back to a shared default.

The approved plan digest was
`0ff1c92c47d9433ac2f30b175d413850f670b813699323264fc785eb6b084a0d`. Migration
`20260823_12` enables and forces all 25 policies for the non-owner, non-superuser,
`NOBYPASSRLS` `athena_app` role. Athena's PostgreSQL pool assumes that role, so missing or empty
tenant context returns no scoped rows and rejects scoped writes. Runtime code must still call
`set_config(..., true)` inside each transaction; session-level tenant settings remain forbidden.

## Runtime tenant context

API sessions derive tenant authority only from the verified `athena_tenant_id` OIDC claim. CLI and
background operations use the explicit `ATHENA_SYSTEM_TENANT_ID`. SQLAlchemy validates the context,
sets it transaction-locally when work begins, and assigns it to new scoped ORM rows. Missing or
invalid authority fails before API database access, while unset, empty, and stale pooled connection
state remains fail closed. Corrective migration `20260824_13` provisions the non-owner runtime login,
and migration `20260824_14` completes composite tenant ownership for requester and approver
references. Administrative migration sessions are explicitly marked and tenant-domain query helpers
reject them because they carry no tenant authority.
