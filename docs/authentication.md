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
- Athena roles from Keycloak realm roles or `athena-api` client roles.

Signing keys are cached and refreshed through PyJWT's JWKS client. Invalid, expired, incorrectly
issued, or incorrectly targeted tokens receive `401 Unauthorized`. Authenticated callers without the
required role receive `403 Forbidden`.

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

The future React dashboard will obtain an access token through the authorization-code-with-PKCE
flow and send it to the API. Current callers can paste a valid access token into the OpenAPI
Authorize dialog or use an HTTP `Authorization` header.

## Authenticated review evidence

Review-open, assignment, and decision payloads no longer accept an `actor` property. The API derives
the actor from the validated `preferred_username` claim. A reviewer can decide only a case assigned
to that authenticated username, preserving both RBAC and case ownership.

`GET /v1/auth/me` returns the validated subject, username, and Athena roles for the current caller.

## Configuration

```dotenv
ATHENA_AUTH_REQUIRED=true
ATHENA_OIDC_ISSUER=http://localhost:8080/realms/athena
ATHENA_OIDC_AUDIENCE=athena-api
ATHENA_OIDC_JWKS_URL=
```

When `ATHENA_OIDC_JWKS_URL` is empty, Athena derives the standard Keycloak certificate endpoint from
the issuer. `ATHENA_AUTH_REQUIRED=false` exists only for isolated development and automated tests;
production deployments must leave authentication enabled.
