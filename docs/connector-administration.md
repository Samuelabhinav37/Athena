# Connector-scope administration

Connector scope changes use a two-command plan/apply workflow through the administrative database
role. `connector-scope-plan` normalizes the provider and scope, checks current state, and emits a
canonical JSON document with a SHA-256 digest. `connector-scope-apply` accepts that saved document
only when `--confirm-plan-sha256` exactly matches. Revalidation inside the write transaction rejects
stale approvals and replayed revocations.

Revocations append evidence and never delete or rewrite the original binding. Applying a scope plan
authorizes only Athena's read-only collection boundary; it does not grant, revoke, or broaden access
at GitHub, Azure, Keycloak, or another provider. `GET /v1/connectors/scopes` exposes active/revoked
status and approval references without credentials or provider secrets.

Migration `20260824_20` changes binding uniqueness from global to tenant-scoped, allowing two tenants
to approve the same provider scope without sharing authority. It must be reviewed and applied before
the administrative workflow is released.
