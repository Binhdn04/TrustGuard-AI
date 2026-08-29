/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TRUSTGUARD_API_URL?: string;
  readonly VITE_TRUSTGUARD_WEB_URL?: string;
  readonly VITE_OIDC_ISSUER?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  readonly VITE_OIDC_AUDIENCE?: string;
  readonly VITE_OIDC_AUTHORIZATION_ENDPOINT?: string;
  readonly VITE_OIDC_TOKEN_ENDPOINT?: string;
  readonly VITE_OIDC_REVOCATION_ENDPOINT?: string;
  readonly VITE_OIDC_ROLES_CLAIM?: string;
  readonly VITE_OIDC_ADMIN_ROLE?: string;
  readonly VITE_OIDC_SCOPE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
