/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_OIDC_AUTHORITY?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  readonly VITE_MOAT_STORE_URL?: string;
  readonly VITE_CLUTTER_STORE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
