export type Role = "user" | "security_admin";

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
}

export interface OidcSession {
  accessToken: string;
  idToken: string;
  refreshToken: string | null;
  expiresAt: number;
  user: User;
}

interface OidcConfig {
  issuer: string;
  clientId: string;
  audience: string | null;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  logoutUrl: string | null;
  rolesClaim: string;
  adminRole: string;
  scope: string;
}

interface OidcTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  returnTo: string;
  createdAt: number;
}

interface TokenResponse {
  access_token?: unknown;
  id_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  token_type?: unknown;
  error?: unknown;
  error_description?: unknown;
}

type JwtClaims = Record<string, unknown>;
type Fetcher = typeof fetch;

const OIDC_SESSION_KEY = "ai_protect_oidc_session";
const OIDC_TRANSACTION_KEY = "ai_protect_oidc_transaction";
const LEGACY_ACCESS_TOKEN_KEY = "ai_protect_access_token";
const DEMO_USER_KEY = "ai_protect_user";
const TRANSACTION_TTL_MS = 10 * 60 * 1000;
const REFRESH_SKEW_MS = 60 * 1000;

function clean(value: string | undefined): string | null {
  const result = value?.trim();
  return result ? result : null;
}

function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function requireHttpsOrLocalhost(value: string, label: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} không phải URL hợp lệ.`);
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error(`${label} phải dùng HTTPS, ngoại trừ localhost.`);
  }
  return url.toString();
}

export function getOidcConfig(): OidcConfig | null {
  const issuerValue = clean(process.env.NEXT_PUBLIC_OIDC_ISSUER);
  const clientId = clean(process.env.NEXT_PUBLIC_OIDC_CLIENT_ID);
  if (!issuerValue || !clientId) return null;

  const issuer = withoutTrailingSlash(requireHttpsOrLocalhost(issuerValue, "OIDC issuer"));
  const legacyLoginUrl = clean(process.env.NEXT_PUBLIC_OIDC_LOGIN_URL);
  const authorizationEndpoint = requireHttpsOrLocalhost(
    clean(process.env.NEXT_PUBLIC_OIDC_AUTHORIZATION_ENDPOINT) ?? legacyLoginUrl ?? `${issuer}/authorize`,
    "OIDC authorization endpoint",
  );
  const tokenEndpoint = requireHttpsOrLocalhost(
    clean(process.env.NEXT_PUBLIC_OIDC_TOKEN_ENDPOINT) ?? `${issuer}/oauth/token`,
    "OIDC token endpoint",
  );
  const logoutValue = clean(process.env.NEXT_PUBLIC_OIDC_LOGOUT_URL);

  return {
    issuer,
    clientId,
    audience: clean(process.env.NEXT_PUBLIC_OIDC_AUDIENCE),
    authorizationEndpoint,
    tokenEndpoint,
    logoutUrl: logoutValue ? requireHttpsOrLocalhost(logoutValue, "OIDC logout URL") : null,
    rolesClaim: clean(process.env.NEXT_PUBLIC_OIDC_ROLES_CLAIM) ?? "roles",
    adminRole: clean(process.env.NEXT_PUBLIC_OIDC_ADMIN_ROLE) ?? "security_admin",
    scope: clean(process.env.NEXT_PUBLIC_OIDC_SCOPE) ?? "openid profile email offline_access",
  };
}

export function isOidcConfigured(): boolean {
  try {
    return getOidcConfig() !== null;
  } catch {
    return false;
  }
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomValue(length = 32): string {
  const bytes = new Uint8Array(length);
  window.crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function codeChallenge(verifier: string): Promise<string> {
  const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

function callbackUri(): string {
  const configured = clean(process.env.NEXT_PUBLIC_OIDC_REDIRECT_URI);
  return configured ?? `${window.location.origin}/auth/callback`;
}

function safeReturnTo(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/auth/callback")) {
    return "/";
  }
  return value;
}

export async function createOidcAuthorizationRequest(returnTo = "/"): Promise<string> {
  const config = getOidcConfig();
  if (!config) throw new Error("OIDC chưa được cấu hình cho frontend.");

  const redirectUri = callbackUri();
  requireHttpsOrLocalhost(redirectUri, "OIDC redirect URI");
  const transaction: OidcTransaction = {
    state: randomValue(),
    nonce: randomValue(),
    codeVerifier: randomValue(64),
    redirectUri,
    returnTo: safeReturnTo(returnTo),
    createdAt: Date.now(),
  };
  window.sessionStorage.setItem(OIDC_TRANSACTION_KEY, JSON.stringify(transaction));

  const url = new URL(config.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", config.scope);
  url.searchParams.set("state", transaction.state);
  url.searchParams.set("nonce", transaction.nonce);
  url.searchParams.set("code_challenge", await codeChallenge(transaction.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  if (config.audience) url.searchParams.set("audience", config.audience);
  return url.toString();
}

function parseJson<T>(value: string | null): T | null {
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

function decodeJwtClaims(token: string): JwtClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("OIDC ID token không đúng định dạng JWT.");
  try {
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as JwtClaims;
  } catch {
    throw new Error("Không thể đọc OIDC ID token.");
  }
}

function claimStrings(value: unknown): string[] {
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

function validateIdentityClaims(claims: JwtClaims, config: OidcConfig, nonce?: string): void {
  if (withoutTrailingSlash(String(claims.iss ?? "")) !== config.issuer) {
    throw new Error("OIDC issuer không khớp cấu hình.");
  }
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claimStrings(claims.aud);
  if (!audiences.includes(config.clientId)) throw new Error("OIDC ID token không dành cho frontend này.");
  if (nonce && claims.nonce !== nonce) throw new Error("OIDC nonce không hợp lệ.");
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= Date.now()) {
    throw new Error("OIDC ID token đã hết hạn.");
  }
  if (typeof claims.sub !== "string" || !claims.sub.trim()) throw new Error("OIDC subject bị thiếu.");
}

function userFromClaims(claims: JwtClaims, config: OidcConfig): User {
  const namespacedRoles = config.audience ? claims[`${withoutTrailingSlash(config.audience)}/roles`] : undefined;
  const roles = new Set([
    ...claimStrings(claims[config.rolesClaim]),
    ...claimStrings(namespacedRoles),
    ...claimStrings(claims.roles),
  ]);
  const email = typeof claims.email === "string" ? claims.email : "";
  const name = typeof claims.name === "string" && claims.name.trim()
    ? claims.name
    : email || "OIDC user";
  return {
    id: String(claims.sub),
    name,
    email,
    role: roles.has(config.adminRole) ? "security_admin" : "user",
  };
}

async function requestTokens(
  config: OidcConfig,
  body: URLSearchParams,
  fetcher: Fetcher,
): Promise<TokenResponse> {
  const response = await fetcher(config.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: body.toString(),
  });
  let payload: TokenResponse;
  try {
    payload = await response.json() as TokenResponse;
  } catch {
    throw new Error("OIDC token endpoint trả về dữ liệu không hợp lệ.");
  }
  if (!response.ok) {
    const description = typeof payload.error_description === "string"
      ? payload.error_description
      : "Identity Provider từ chối yêu cầu token.";
    throw new Error(description);
  }
  return payload;
}

function tokenExpiry(payload: TokenResponse, accessToken: string): number {
  const accessClaims = (() => {
    try { return decodeJwtClaims(accessToken); } catch { return null; }
  })();
  const jwtExpiry = typeof accessClaims?.exp === "number" ? accessClaims.exp * 1000 : null;
  const seconds = typeof payload.expires_in === "number" && payload.expires_in > 0
    ? payload.expires_in
    : 300;
  return jwtExpiry ?? Date.now() + seconds * 1000;
}

export async function completeOidcAuthorization(
  search: string,
  fetcher: Fetcher = fetch,
): Promise<{ session: OidcSession; returnTo: string }> {
  const config = getOidcConfig();
  if (!config) throw new Error("OIDC chưa được cấu hình cho frontend.");
  const query = new URLSearchParams(search);
  const providerError = query.get("error_description") ?? query.get("error");
  if (providerError) throw new Error(providerError);
  const code = query.get("code");
  const state = query.get("state");
  if (!code || !state) throw new Error("OIDC callback thiếu code hoặc state.");

  const transaction = parseJson<OidcTransaction>(window.sessionStorage.getItem(OIDC_TRANSACTION_KEY));
  window.sessionStorage.removeItem(OIDC_TRANSACTION_KEY);
  if (!transaction || state !== transaction.state) throw new Error("OIDC state không hợp lệ.");
  if (Date.now() - transaction.createdAt > TRANSACTION_TTL_MS) throw new Error("OIDC login đã hết thời gian chờ.");

  const payload = await requestTokens(config, new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    code,
    code_verifier: transaction.codeVerifier,
    redirect_uri: transaction.redirectUri,
  }), fetcher);
  if (typeof payload.access_token !== "string" || typeof payload.id_token !== "string") {
    throw new Error("OIDC token response thiếu access token hoặc ID token.");
  }
  if (payload.token_type && String(payload.token_type).toLowerCase() !== "bearer") {
    throw new Error("OIDC token type không được hỗ trợ.");
  }

  // These claims only drive optimistic frontend presentation. The FastAPI
  // boundary independently verifies the access-token signature and RBAC.
  const claims = decodeJwtClaims(payload.id_token);
  validateIdentityClaims(claims, config, transaction.nonce);
  const session: OidcSession = {
    accessToken: payload.access_token,
    idToken: payload.id_token,
    refreshToken: typeof payload.refresh_token === "string" ? payload.refresh_token : null,
    expiresAt: tokenExpiry(payload, payload.access_token),
    user: userFromClaims(claims, config),
  };
  saveOidcSession(session);
  return { session, returnTo: safeReturnTo(transaction.returnTo) };
}

export function saveOidcSession(session: OidcSession): void {
  window.sessionStorage.setItem(OIDC_SESSION_KEY, JSON.stringify(session));
  window.localStorage.removeItem(LEGACY_ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(DEMO_USER_KEY);
}

export function loadOidcSession(): OidcSession | null {
  const session = parseJson<OidcSession>(window.sessionStorage.getItem(OIDC_SESSION_KEY));
  if (!session || typeof session.accessToken !== "string" || typeof session.expiresAt !== "number") {
    window.sessionStorage.removeItem(OIDC_SESSION_KEY);
    return null;
  }
  return session;
}

export function getStoredAccessToken(): string | null {
  const session = loadOidcSession();
  if (!session || session.expiresAt <= Date.now()) return null;
  return session.accessToken;
}

export async function refreshOidcSession(
  session: OidcSession,
  fetcher: Fetcher = fetch,
): Promise<OidcSession> {
  if (!session.refreshToken) {
    if (session.expiresAt <= Date.now()) throw new Error("OIDC session đã hết hạn.");
    return session;
  }
  const config = getOidcConfig();
  if (!config) throw new Error("OIDC chưa được cấu hình cho frontend.");
  const payload = await requestTokens(config, new URLSearchParams({
    grant_type: "refresh_token",
    client_id: config.clientId,
    refresh_token: session.refreshToken,
  }), fetcher);
  if (typeof payload.access_token !== "string") throw new Error("OIDC refresh response thiếu access token.");
  const nextIdToken = typeof payload.id_token === "string" ? payload.id_token : session.idToken;
  let user = session.user;
  if (typeof payload.id_token === "string") {
    const claims = decodeJwtClaims(payload.id_token);
    validateIdentityClaims(claims, config);
    user = userFromClaims(claims, config);
  }
  const refreshed: OidcSession = {
    accessToken: payload.access_token,
    idToken: nextIdToken,
    refreshToken: typeof payload.refresh_token === "string" ? payload.refresh_token : session.refreshToken,
    expiresAt: tokenExpiry(payload, payload.access_token),
    user,
  };
  saveOidcSession(refreshed);
  return refreshed;
}

export async function restoreOidcSession(fetcher: Fetcher = fetch): Promise<OidcSession | null> {
  const session = loadOidcSession();
  if (!session) return null;
  if (session.expiresAt - Date.now() > REFRESH_SKEW_MS) return session;
  try {
    return await refreshOidcSession(session, fetcher);
  } catch {
    clearOidcSession();
    return null;
  }
}

export function clearOidcSession(): void {
  window.sessionStorage.removeItem(OIDC_SESSION_KEY);
  window.sessionStorage.removeItem(OIDC_TRANSACTION_KEY);
  window.localStorage.removeItem(LEGACY_ACCESS_TOKEN_KEY);
}

export function oidcRefreshDelay(session: OidcSession): number {
  const skew = session.refreshToken ? REFRESH_SKEW_MS : 0;
  return Math.max(0, session.expiresAt - Date.now() - skew);
}

export function getOidcLogoutUrl(): string | null {
  return getOidcConfig()?.logoutUrl ?? null;
}
