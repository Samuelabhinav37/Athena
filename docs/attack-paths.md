# Neo4j attack-path analysis

Athena projects active authorization provenance from PostgreSQL into Neo4j for bounded, read-only
path queries. PostgreSQL remains the system of record. Neo4j is a derived analytical index: graph
results are advisory and cannot grant, deny, revoke, approve, or execute access changes.

## Configuration

Set `NEO4J_AUTH` for the local container and configure Athena with
`ATHENA_NEO4J_ENABLED=true`, `ATHENA_NEO4J_URL`, `ATHENA_NEO4J_USER`, and
`ATHENA_NEO4J_PASSWORD`. Do not commit credentials. The local service uses the pinned Community
image `neo4j:2026.06.0-community` and exposes Browser on port 7474 and Bolt on port 7687. The demo
stack keeps both ports private to its Compose network.

## Projection

After PostgreSQL synchronization and provenance materialization, explicitly project active lineage:

```bash
python -m athena.cli project-attack-graph
```

The projection uses stable canonical UUIDs and idempotent `MERGE` operations. It never alters
PostgreSQL. This foundation does not remove stale graph nodes or relationships automatically;
operators must treat graph freshness as separate from authoritative evidence freshness.

## Query API

`GET /v1/attack-paths/identities/{identity_id}` requires the Athena viewer role. `max_depth` is
bounded from 1 to 8 and `limit` from 1 to 100. Only paths reaching a resource through a privileged
entitlement are returned, ordered shortest-first. Responses contain node identifiers, kinds, labels,
and provenance relationship names—not credentials, tokens, source metadata, or policy inputs.

## Safety boundary

- Graph projection is one-way from PostgreSQL evidence to Neo4j.
- Neo4j findings never feed OPA, remediation decisions, or execution adapters.
- The API is query-only and bounded against path explosion.
- Production deployments require TLS, externally managed credentials, backup policy, and graph
  freshness monitoring.
