function clean(value) {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function exactEndpoint(value, label, issuerOrigin = null) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute URL.`);
  }
  const localhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(localhost && url.protocol === "http:")) {
    throw new Error(`${label} must use HTTPS except on localhost.`);
  }
  if (
    url.hostname.includes("*") ||
    (issuerOrigin !== null && url.origin !== issuerOrigin) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${label} must use the exact issuer origin without wildcard, credentials, query or fragment.`);
  }
  return url;
}

function exactApiOrigin(value) {
  const url = exactEndpoint(value, "TrustGuard API URL");
  if (url.hostname.includes("*") || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(
      "TrustGuard API URL must be an exact origin without wildcard, path, query or fragment.",
    );
  }
  return url.origin;
}

export function resolveOidcBuildPolicy(environment) {
  if (clean(environment.VITE_OIDC_CLIENT_SECRET)) {
    throw new Error("A Chrome Extension public client must never define VITE_OIDC_CLIENT_SECRET.");
  }
  const issuerValue = clean(environment.VITE_OIDC_ISSUER);
  const clientId = clean(environment.VITE_OIDC_CLIENT_ID);
  const audience = clean(environment.VITE_OIDC_AUDIENCE);
  const configuredValues = [issuerValue, clientId, audience].filter(Boolean);
  if (configuredValues.length > 0 && (!issuerValue || !clientId || !audience)) {
    throw new Error("VITE_OIDC_ISSUER, VITE_OIDC_CLIENT_ID and VITE_OIDC_AUDIENCE must be configured together.");
  }
  const origins = new Set();
  const connectSources = new Set();
  if (issuerValue && clientId && audience) {
    const issuer = exactEndpoint(issuerValue, "OIDC issuer");
    const issuerOrigin = issuer.origin;
    exactEndpoint(
      clean(environment.VITE_OIDC_AUTHORIZATION_ENDPOINT) ?? `${issuer.href.replace(/\/+$/, "")}/authorize`,
      "OIDC authorization endpoint",
      issuerOrigin,
    );
    const token = exactEndpoint(
      clean(environment.VITE_OIDC_TOKEN_ENDPOINT) ?? `${issuer.href.replace(/\/+$/, "")}/oauth/token`,
      "OIDC token endpoint",
      issuerOrigin,
    );
    const revocationValue = clean(environment.VITE_OIDC_REVOCATION_ENDPOINT);
    const scope = clean(environment.VITE_OIDC_SCOPE) ?? "openid profile email offline_access";
    if (!scope.split(/\s+/u).includes("openid")) throw new Error("OIDC scope must include openid.");
    origins.add(token.origin);
    connectSources.add(token.origin);
    if (revocationValue) {
      const revocationOrigin = exactEndpoint(revocationValue, "OIDC revocation endpoint", issuerOrigin).origin;
      origins.add(revocationOrigin);
      connectSources.add(revocationOrigin);
    }
  }
  const apiValue = clean(environment.VITE_TRUSTGUARD_API_URL);
  if (apiValue) {
    const apiOrigin = exactApiOrigin(apiValue);
    origins.add(apiOrigin);
    connectSources.add(apiOrigin);
    const streamOrigin = new URL(apiOrigin);
    streamOrigin.protocol = streamOrigin.protocol === "https:" ? "wss:" : "ws:";
    connectSources.add(streamOrigin.origin);
  }
  const webValue = clean(environment.VITE_TRUSTGUARD_WEB_URL);
  if (webValue) exactApiOrigin(webValue);
  const exactOrigins = [...origins].sort();
  const exactConnectSources = [...connectSources].sort();
  if (exactConnectSources.length === 0) {
    return { configured: false, connectSource: "'none'", hostPermissions: undefined };
  }
  return {
    configured: true,
    connectSource: exactConnectSources.join(" "),
    hostPermissions: exactOrigins.map((origin) => `${origin}/*`),
  };
}
