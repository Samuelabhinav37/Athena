# Contributing to Athena

Thank you for helping build Athena.

## Development principles

- Keep authorization decisions deterministic and testable.
- Treat model output as a recommendation or explanation, never as policy truth.
- Preserve provenance and audit context across every state transition.
- Never log credentials, tokens, private keys, or unnecessary personal data.
- Prefer small changes with tests and an explicit security impact.

## Workflow

1. Create a branch from `main`.
2. Add or update tests with the change.
3. Run the local checks.
4. Open a pull request describing behavior, security impact, and validation.

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
```

Policy changes must include Rego tests and examples of expected allow, deny, and malformed-input behavior.

## Commit messages

Use short imperative summaries, such as `Add entitlement provenance schema`. Keep refactoring separate from behavioral changes where practical.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
