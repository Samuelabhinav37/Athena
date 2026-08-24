# OIDC authentication and API authorization

Athena validates Keycloak access tokens locally against the realm JSON Web Key Set. The API does not
accept passwords, introspect every request remotely, or trust identity fields supplied in request
payloads.

## Validation boundary

Every protected request must present `Authorization: Bearer <access-token>`. Athena verifies:

- an RSA signature using the realm JWKS and an explicit `RS256` algorithm allow-list;
- issuer equality with `ATHENA_OIDC_ISSUER`;
- the `ATHENA_OIDC_AUDIENCE` audience (`athena-api` by default);
- required `exp`, `iat`, `sub`, `iss`, and `aud` claims; and
- a canonical `athena_tenant_id` authority claim before database access; and
- Athena roles from Keycloak realm roles or `athena-api` client roles.

Signing keys are cached and refreshed through PyJWT's JWKS client. Invalid, expired, incorrectly
issued, or incorrectly targeted tokens receive `401 Unauthorized`. Authenticated callers without the
required role or a valid tenant claim receive `403 Forbidden`.

The local Keycloak lab emits `athena_tenant_id=athena-local`. Athena validates that claim against its
canonical tenant-ID contract and installs it with transaction-local PostgreSQL `set_config`. It is
never accepted from request bodies, query parameters, provider metadata, or session-level database
settings. A pooled connection therefore returns to fail-closed state after commit or rollback.

## Role hierarchy

| Role | Access |
|---|---|
| `athena-viewer` | Read identities, entitlements, policy/risk/anomaly evidence, reviews, connectors, and monitoring runs |
| `athena-analyst` | Viewer access plus opening reviews |
| `athena-reviewer` | Analyst access plus assigning and deciding reviews |
| `athena-administrator` | Reviewer access plus reserved administrative and execution operations |

The realm models these as composite roles. Higher roles include lower-role capabilities. The local
Acme Corp assignments are:

- Alice, David, and Emma: viewer;
- Bob: analyst;
- Charlie: reviewer; and
- Frank: administrator.

## Keycloak clients

- `athena-api` remains bearer-only and is the required access-token audience.
- `athena-web` remains a public authorization-code client with PKCE S256.
- An audience mapper adds `athena-api` only to access tokens.
- Password grants remain disabled for every client.

The React dashboard obtains an access token through the authorization-code-with-PKCE flow and sends
it to the API. API-only callers can use the OpenAPI Authorize dialog or an HTTP `Authorization`
header with a valid access token.

## Authenticated review evidence

Review-open, assignment, and decision payloads no longer accept an `actor` property. The API derives
the actor from the validated `preferred_username` claim. A reviewer can decide only a case assigned
to that authenticated username, preserving both RBAC and case ownership.

`GET /v1/auth/me` returns the validated subject, username, and Athena roles for the current caller.

## Configuration

```dotenv
ATHENA_AUTH_REQUIRED=true
ATHENA_SYSTEM_TENANT_ID=athena-local
ATHENA_OIDC_ISSUER=http://localhost:8080/realms/athena
ATHENA_OIDC_AUDIENCE=athena-api
ATHENA_OIDC_JWKS_URL=
ATHENA_OIDC_IDENTITY_SOURCE=keycloak
```

When `ATHENA_OIDC_JWKS_URL` is empty, Athena derives the standard Keycloak certificate endpoint from
the issuer. `ATHENA_AUTH_REQUIRED=false` exists only for isolated development and automated tests;
production deployments must leave authentication enabled.
`ATHENA_OIDC_IDENTITY_SOURCE` identifies the normalized connector source trusted for subject-to-
tenant membership. It defaults to `keycloak`; deployments using another OIDC authority must set it
to the matching normalized identity source, such as `azure_entra`. A matching subject from any other
source does not establish membership.
`ATHENA_SYSTEM_TENANT_ID` is used only by the explicit authentication-disabled development path.
Tenant-scoped CLI commands and background jobs require their own `--tenant-id` argument.
