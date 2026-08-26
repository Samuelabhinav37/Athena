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

## Windows desktop preview

The Tauri shell reuses the same React dashboard and keeps Athena's API, identity provider,
policy engine, connectors, and evidence store on the server. It does not expose native commands
to the webview or store service credentials on the analyst workstation.

Prerequisites:

1. Install the Rust stable MSVC toolchain and Microsoft's C++ build tools.
2. Start Athena's local API and identity services.
3. Run `npm run desktop:dev` from this directory.

Create Windows installers with `npm run desktop:build`. Installers are written beneath
`src-tauri/target/release/bundle`. The current shell is a local preview: production distribution
still requires a desktop-safe OIDC callback, HTTPS server configuration, code signing, and an
update policy.
