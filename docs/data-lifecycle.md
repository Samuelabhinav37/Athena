# Data lifecycle and recovery contract

PostgreSQL is Athena's evidence system of record. The machine-readable contract is
`governance/data-lifecycle.json`; startup and release checks must reject changes that weaken its
encryption, approval, export-digest, or audit requirements.

Backups must be encrypted, remain inside the deployment-approved region set, meet the declared
15-minute recovery-point objective, and be exercised by a restore test at least every 30 days. A
restore is successful only when migrations reach head, tenant isolation tests pass, immutable-table
triggers and privileges match the model, and evidence counts and sampled digests reconcile with the
backup manifest.

Athena never performs automatic evidence deletion. Any legal or contractual deletion workflow must
first produce a portable export and digest, reference an explicit human approval, execute through an
administrative runbook outside the application role, and append an audit record describing scope and
outcome. Residency changes and cross-region replication require a separate reviewed infrastructure
change; connector metadata never supplies residency authority.
