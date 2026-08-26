# Vendor-neutral IAM connector contract

Athena connector contract `1.0` standardizes how an IAM adapter declares its evidence boundary
without forcing provider-specific snapshots into a lossy universal payload. Existing GitHub,
Microsoft Azure, and Keycloak collection results remain unchanged.

## Manifest contract

Every connector exposes a frozen, unknown-field-rejecting `ConnectorManifest` containing a stable
connector ID, provider and display names, contract version, `read_only: true`, and
`data_authority: evidence_only`. The manifest is configuration and secret free; it must be safe to
return from a status surface or include in conformance evidence.

Every capability is mandatory and has one of three explicit support levels:

- `supported`: the current adapter implements the capability within its documented boundary;
- `partial`: useful evidence is collected, but a named semantic gap remains; or
- `unsupported`: consumers must not infer the capability from adjacent data.

Partial and unsupported declarations require a meaningful limitation. The complete capability set
is identity discovery, pagination, incremental cursors, retries, collection freshness,
authorization inheritance, nested groups, deny rules, privileged eligibility, machine identities,
and activity signals.

## Current compatibility matrix

| Capability | GitHub | Microsoft Azure | Keycloak |
|---|---|---|---|
| Identity discovery | Supported | Supported | Supported |
| Pagination | Supported | Supported | Supported |
| Incremental cursors | Partial: endpoint ETags | Unsupported | Unsupported |
| Retries | Unsupported | Unsupported | Unsupported |
| Collection freshness | Partial: sync layer | Partial: sync layer | Unsupported |
| Authorization inheritance | Partial | Partial | Partial |
| Nested groups | Unsupported | Partial: direct IDs | Partial: paths only |
| Deny rules | Unsupported | Unsupported | Unsupported |
| Privileged eligibility | Unsupported | Unsupported | Unsupported |
| Machine identities | Unsupported | Supported | Unsupported |
| Activity signals | Unsupported | Unsupported | Unsupported |

These declarations describe collected evidence, not the provider's full product capability. A
manifest never authorizes writes, makes policy decisions, or upgrades incomplete evidence into an
authoritative fact. Future snapshot, cursor, freshness, and retry contracts must preserve existing
source provenance and fail closed on incomplete collection.
