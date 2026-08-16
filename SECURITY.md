# Security policy

## Supported versions

Athena is pre-release software. Security fixes currently target the latest commit on `main`.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in public issues, discussions, or pull requests. Use GitHub's private vulnerability reporting feature for this repository when available. Include:

- the affected component and revision;
- reproduction steps or a proof of concept;
- the expected and observed security impact; and
- any suggested mitigation.

Do not access data that is not yours, degrade a third-party service, or perform destructive testing. We will acknowledge a complete report as soon as maintainers are available and coordinate disclosure after a fix is ready.

## Scope expectations

High-impact areas include authorization bypasses, provenance or audit tampering, unsafe remediation, secret exposure, cross-tenant access, policy-evaluation inconsistencies, and ways for ML or LLM output to influence deterministic decisions.
