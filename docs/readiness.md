# Release readiness

`governance/readiness.json` is the canonical reconciliation manifest for the enterprise hardening
workstreams. Each entry names repository evidence and distinguishes implemented controls from code
that still requires an approved database migration. A release cannot claim readiness while any entry
is `pending_migration` or `blocked`, even when unit tests pass.

Promotion requires the Python and PostgreSQL suites, Rego tests, migration drift check, deterministic
security gate, disposable restore exercise, and supply-chain workflow. Operational ownership must
also supply approved regions, backup storage, alert destinations, OIDC issuer administration, and
break-glass custodians; repository defaults are not production approvals.
