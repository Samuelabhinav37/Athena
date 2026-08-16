# Athena policies

This directory contains deterministic OPA/Rego governance policies and their tests.

Planned namespaces:

- `iam` for entitlement and privileged-access requirements;
- `authentication` for MFA and authentication-context requirements;
- `sod` for separation-of-duties constraints; and
- `grc` for machine-readable control mappings.

Policy changes must be reviewed and tested before deployment.

Run the deterministic policy tests with:

```bash
docker compose run --rm opa test /policies -v
```

`iam/authorization.rego` evaluates one effective entitlement at a time. Its output contains only an `allow` boolean and structured violations. OPA never receives remediation credentials and cannot modify access.
