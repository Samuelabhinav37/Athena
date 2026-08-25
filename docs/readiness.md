# Release readiness

`governance/readiness.json` is the canonical reconciliation manifest for the enterprise hardening
workstreams and production promotion. It deliberately distinguishes two claims:

- `implementation_ready` means every repository workstream is implemented and its evidence exists;
- `production_ready` additionally requires `production_status: ready` and no deployment blockers.

Athena is implementation-ready but not production-ready. Passing tests and implemented controls do
not substitute for deployment-specific recovery and operational evidence.

Promotion requires the Python and disposable PostgreSQL suites, Rego tests, migration drift check,
deterministic security gate, and supply-chain workflow. Operational ownership must also close every
`production_blockers` entry—including a real isolated restore rehearsal—with approved platform
evidence. Repository defaults, local connector runs, and disposable schema tests are not production
approvals.

The ordered Azure baseline, human decision points, recovery rehearsal, and promotion gates are in
[production deployment and recovery plan](production-deployment-plan.md). The checked-in
`governance/production-evidence.example.json` is a placeholder schema only and must never be treated
as completed evidence.
