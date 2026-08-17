# Athena web dashboard

Authenticated React dashboard for Athena's identity-governance evidence APIs.

## Run locally

1. Start Athena's PostgreSQL, Keycloak, OPA, and API services.
2. Copy `.env.example` to `.env.local` only when you need non-default endpoints.
3. Run `npm install` and `npm run dev` from this directory.
4. Open <http://localhost:3000> and sign in through the local Athena realm.

Vite proxies protected API requests to `http://localhost:8000`, keeping access tokens out of URLs
and avoiding a permissive API CORS policy. Authentication uses authorization code with PKCE S256.

## Checks

```powershell
npm run typecheck
npm run build
```
