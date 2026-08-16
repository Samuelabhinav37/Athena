# Athena

**Continuous authorization provenance and identity-governance evidence.**

Athena is an open-source identity-governance platform built to answer five questions for every identity:

> Who are you? What can you access? Why can you access it? Are you still supposed to have it? Can we prove that to an auditor?

Athena normalizes identity and entitlement data, preserves the lineage behind effective access, evaluates deterministic policies, detects identity drift, and produces continuously updated compliance evidence.

## Guiding principle

> The LLM explains. ML recommends. The policy engine decides. A human approves destructive actions.

## MVP

Version 0.1 focuses on one complete, auditable scenario: an employee changes roles while retaining access from the previous role. Athena will:

- ingest users, groups, roles, and entitlements from a controlled Keycloak lab;
- trace every effective permission to its source, approval, justification, and expiration;
- flag missing governance data and deterministic policy violations with OPA/Rego;
- detect peer anomalies and calculate an explainable access-decay score;
- generate live evidence for NIST SP 800-53 AC-2, AC-5, and AC-6;
- translate findings into plain language with a local Ollama model; and
- require a recorded human decision before removing access.

## Architecture

The initial platform uses:

- **FastAPI** for APIs, collection, normalization, and orchestration
- **PostgreSQL** as the system of record for identities, entitlements, provenance, decisions, and audit events
- **Keycloak** as the controlled identity provider
- **OPA/Rego** for deterministic policy evaluation
- **scikit-learn** for interpretable peer and anomaly analytics
- **Ollama** for local explanations only
- **React** for the security and audit interface

Neo4j, workload-identity governance, attack-path analysis, and autonomous low-risk remediation are planned after the core data and policy model is proven.

See [docs/architecture.md](docs/architecture.md) for boundaries, the build sequence, and acceptance criteria.

For the complete chronological record—including completed work, decisions, errors, resolutions, validation evidence, and next steps—see the [project journal](docs/project-journal.md).

## Repository layout

```text
apps/
  api/                 FastAPI application
  web/                 React application (introduced later)
docs/                  Architecture and project decisions
infra/                 Local infrastructure and future IaC
policies/              OPA/Rego policies and tests
tests/                 Cross-service and acceptance tests
```

## Local development

Prerequisites:

- Docker with Docker Compose
- Python 3.12+

Start the controlled identity infrastructure:

```bash
docker compose up -d postgres keycloak opa
```

The version-controlled Acme Corp realm is imported automatically on first start. See [infra/keycloak/README.md](infra/keycloak/README.md) for seeded identities, local credentials, and reset behavior.

Create a Python environment and run the API:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
alembic upgrade head
uvicorn athena.main:app --reload --app-dir apps/api/src
```

Then visit `http://localhost:8000/health`, `http://localhost:8000/ready`, or the interactive API documentation at `http://localhost:8000/docs`.

Synchronize the controlled Keycloak identities into PostgreSQL:

```bash
python -m athena.cli sync-keycloak
```

The command uses a dedicated read-only Keycloak service account and prints only synchronization counts; it never prints tokens or credentials.

Seed and materialize the controlled authorization-provenance scenario:

```bash
python -m athena.cli seed-provenance-demo
```

After starting the API, retrieve an identity's effective access and ordered provenance chains from `GET /v1/identities/{identity_id}/entitlements`.

Copy `.env.example` to `.env` before changing the local defaults. Never commit `.env` or production secrets.

## Current status

Athena is in early development. The first milestone is the controlled Acme Corp identity lab and canonical identity backbone.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change. Do not disclose suspected vulnerabilities in a public issue; follow [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
