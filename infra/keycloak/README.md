# Controlled Keycloak identity lab

`realm-athena.json` defines the reproducible Acme Corp ground-truth environment used by Athena's acceptance tests and demonstrations.

## Included identities

| Username | Department | Initial role | Manager |
|---|---|---|---|
| `alice` | Engineering | Developer | Bob |
| `bob` | DevOps | DevOps Engineer, Cloud Admin | Frank |
| `charlie` | Security | Security Analyst | Frank |
| `david` | Finance | Finance Analyst | Frank |
| `emma` | HR | HR Specialist | Frank |
| `frank` | IT | Athena Administrator, DB Admin, Cloud Admin | — |

The shared initial user password is `AthenaLab1!` and is marked temporary. These credentials are deliberately limited to the disposable local lab and must never be reused in another environment.

## Start the lab

From the repository root:

```bash
docker compose up -d postgres keycloak opa
docker compose logs -f keycloak
```

Keycloak is available at `http://localhost:8080`. The administration console uses the bootstrap credentials in `.env`; defaults are `admin` / `change-me`.

The realm import runs only when the `athena` realm does not already exist. To apply a changed seed configuration to an existing disposable lab, explicitly remove the local containers and volumes before starting again:

```bash
docker compose down --volumes
docker compose up -d
```

Removing volumes permanently deletes local lab data. Do not run that command against an environment containing data you intend to keep.

## Scenario baseline

Alice begins in Engineering with the `developer` role. Her later transfer to Security will be modeled as a separate, auditable event so Athena can detect retained developer and production-support access rather than hiding the drift in the seed state.
