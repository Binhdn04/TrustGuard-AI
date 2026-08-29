export interface OidcConfig {
  issuer: string;
  clientId: string;
  audience: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  revocationEndpoint: string | null;
  rolesClaim: string;
  adminRole: string;
  scope: string;
}

export type OidcEnvironment = Record<string, string | undefined>;

function clean(value: string | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function parseLocalHttpsUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute URL.`);
  }
  const localhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(localhost && url.protocol === "http:")) {
    throw new Error(`${label} must use HTTPS except on localhost.`);
  }
  if (url.hostname.includes("*") || url.username || url.password || url.search || url.hash) {
    throw new Error(`${label} cannot contain a wildcard, credentials, query or fragment.`);
  }
  return url;
}

function endpoint(value: string, label: string, issuerOrigin: string): string {
  const url = parseLocalHttpsUrl(value, label);
  if (url.origin !== issuerOrigin) {
    throw new Error(`${label} must use the exact OIDC issuer origin.`);
  }
  return url.href;
}

export function resolveOidcConfig(environment: OidcEnvironment): OidcConfig | null {
  const issuerValue = clean(environment.VITE_OIDC_ISSUER);
  const clientId = clean(environment.VITE_OIDC_CLIENT_ID);
  const audience = clean(environment.VITE_OIDC_AUDIENCE);
  if (!issuerValue && !clientId && !audience) return null;
  if (!issuerValue || !clientId || !audience) {
    throw new Error("OIDC issuer, public client ID and API audience must be configured together.");
  }

  const issuerUrl = parseLocalHttpsUrl(issuerValue, "OIDC issuer");
  const issuer = issuerUrl.href.replace(/\/+$/, "");
  const authorizationEndpoint = endpoint(
    clean(environment.VITE_OIDC_AUTHORIZATION_ENDPOINT) ?? `${issuer}/authorize`,
    "OIDC authorization endpoint",
    issuerUrl.origin,
  );
  const tokenEndpoint = endpoint(
    clean(environment.VITE_OIDC_TOKEN_ENDPOINT) ?? `${issuer}/oauth/token`,
    "OIDC token endpoint",
    issuerUrl.origin,
  );
  const revocationValue = clean(environment.VITE_OIDC_REVOCATION_ENDPOINT);
  const scope = clean(environment.VITE_OIDC_SCOPE) ?? "openid profile email offline_access";
  if (!scope.split(/\s+/u).includes("openid")) {
    throw new Error("OIDC scope must include openid.");
  }

  return {
    issuer,
    clientId,
    audience,
    authorizationEndpoint,
    tokenEndpoint,
    revocationEndpoint: revocationValue
      ? endpoint(revocationValue, "OIDC revocation endpoint", issuerUrl.origin)
      : null,
    rolesClaim: clean(environment.VITE_OIDC_ROLES_CLAIM) ?? "roles",
    adminRole: clean(environment.VITE_OIDC_ADMIN_ROLE) ?? "security_admin",
    scope,
  };
}

export function getBundledOidcConfig(): OidcConfig | null {
  return resolveOidcConfig(import.meta.env);
}
