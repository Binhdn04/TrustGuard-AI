import type { OidcConfig } from "./config";
import type { AuthErrorCode, AuthPublicState } from "./public-state";
import {
  AUTH_TRANSACTION_TTL_MS,
  type AuthSession,
  type AuthSessionStore,
  type AuthTransaction,
} from "./session-store";

export class AuthFlowError extends Error {
  constructor(readonly code: AuthErrorCode) {
    super(code);
    this.name = "AuthFlowError";
  }
}

interface IdentityApi {
  getRedirectURL(path?: string): string;
  launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>;
}

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
type JwtClaims = Record<string, unknown>;

export interface OidcAuthDependencies {
  config: OidcConfig | null;
  store: AuthSessionStore;
  identity: IdentityApi;
  fetcher?: Fetcher;
  now?: () => number;
  randomValue?: (bytes?: number) => string;
  codeChallenge?: (verifier: string) => Promise<string>;
}

const REFRESH_SKEW_MS = 60_000;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function secureRandomValue(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64Url(value);
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

function decodeJwt(token: string): JwtClaims {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[1] === undefined) throw new AuthFlowError("invalid_token");
  try {
    const normalized = parts[1].replace(/-/gu, "+").replace(/_/gu, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), (item) => item.charCodeAt(0)))) as JwtClaims;
  } catch {
    throw new AuthFlowError("invalid_token");
  }
}

function claimStrings(value: unknown): string[] {
  if (typeof value === "string") return value.split(/\s+/u).filter(Boolean);
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return [];
}

function validateClaims(
  claims: JwtClaims,
  expectedIssuer: string,
  expectedAudience: string,
  now: number,
  nonce?: string,
): void {
  if (typeof claims.iss !== "string" || claims.iss.replace(/\/+$/u, "") !== expectedIssuer) {
    throw new AuthFlowError("invalid_token");
  }
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claimStrings(claims.aud);
  if (!audiences.includes(expectedAudience)) throw new AuthFlowError("invalid_token");
  if (nonce !== undefined && claims.nonce !== nonce) throw new AuthFlowError("invalid_token");
  if (typeof claims.exp !== "number" || claims.exp * 1_000 <= now) throw new AuthFlowError("expired");
  if (typeof claims.sub !== "string" || claims.sub.trim().length === 0) {
    throw new AuthFlowError("invalid_token");
  }
}

function exactRedirect(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthFlowError("redirect_mismatch");
  }
  if (url.protocol !== "https:" || !url.hostname.endsWith(".chromiumapp.org") || url.hash.length > 0) {
    throw new AuthFlowError("redirect_mismatch");
  }
  return `${url.origin}${url.pathname}`;
}

function userFromClaims(claims: JwtClaims, config: OidcConfig): AuthSession["user"] {
  const roles = new Set([
    ...claimStrings(claims[config.rolesClaim]),
    ...claimStrings(claims[`${config.audience.replace(/\/+$/u, "")}/roles`]),
    ...claimStrings(claims.roles),
  ]);
  const email = typeof claims.email === "string" ? claims.email : "";
  const name = typeof claims.name === "string" && claims.name.trim() ? claims.name : email || "OIDC user";
  return {
    id: String(claims.sub),
    name,
    email,
    role: roles.has(config.adminRole) ? "security_admin" : "user",
  };
}

interface TokenResponse {
  access_token?: unknown;
  id_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  token_type?: unknown;
}

export class OidcAuthManager {
  private readonly fetcher: Fetcher;
  private readonly now: () => number;
  private readonly randomValue: (bytes?: number) => string;
  private readonly codeChallenge: (verifier: string) => Promise<string>;

  constructor(private readonly dependencies: OidcAuthDependencies) {
    this.fetcher = dependencies.fetcher ?? fetch;
    this.now = dependencies.now ?? Date.now;
    this.randomValue = dependencies.randomValue ?? secureRandomValue;
    this.codeChallenge = dependencies.codeChallenge ?? pkceChallenge;
  }

  private requireConfig(): OidcConfig {
    if (this.dependencies.config === null) throw new AuthFlowError("not_configured");
    return this.dependencies.config;
  }

  async publicState(): Promise<AuthPublicState> {
    if (this.dependencies.config === null) return { status: "not_configured" };
    const session = await this.dependencies.store.readSession();
    if (session === null) return { status: "signed_out" };
    if (session.expiresAt > this.now()) return { status: "signed_in" };
    if (session.refreshToken !== null) return { status: "signed_in" };
    await this.dependencies.store.clearAll();
    return { status: "signed_out" };
  }

  async beginAuthorization(): Promise<string> {
    const config = this.requireConfig();
    const redirectUri = this.dependencies.identity.getRedirectURL("oidc");
    exactRedirect(redirectUri);
    const transaction: AuthTransaction = {
      version: 1,
      state: this.randomValue(),
      nonce: this.randomValue(),
      codeVerifier: this.randomValue(64),
      redirectUri,
      createdAt: this.now(),
    };
    await this.dependencies.store.saveTransaction(transaction);
    const url = new URL(config.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", config.scope);
    url.searchParams.set("audience", config.audience);
    url.searchParams.set("state", transaction.state);
    url.searchParams.set("nonce", transaction.nonce);
    url.searchParams.set("code_challenge", await this.codeChallenge(transaction.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");
    return url.href;
  }

  async login(): Promise<AuthPublicState> {
    try {
      const authorizationUrl = await this.beginAuthorization();
      const finalUrl = await this.dependencies.identity.launchWebAuthFlow({
        url: authorizationUrl,
        interactive: true,
      });
      if (finalUrl === undefined) throw new AuthFlowError("canceled");
      await this.completeAuthorization(finalUrl);
      return { status: "signed_in" };
    } catch (error: unknown) {
      await this.dependencies.store.clearAll();
      if (error instanceof AuthFlowError) throw error;
      throw new AuthFlowError("network");
    }
  }

  async completeAuthorization(finalUrl: string): Promise<AuthSession> {
    const config = this.requireConfig();
    const transaction = await this.dependencies.store.readTransaction();
    if (transaction === null) throw new AuthFlowError("state_mismatch");
    try {
      const callback = new URL(finalUrl);
      if (
        exactRedirect(finalUrl) !== exactRedirect(transaction.redirectUri) ||
        exactRedirect(transaction.redirectUri) !== exactRedirect(this.dependencies.identity.getRedirectURL("oidc"))
      ) {
        throw new AuthFlowError("redirect_mismatch");
      }
      if (callback.searchParams.has("error")) throw new AuthFlowError("canceled");
      const code = callback.searchParams.get("code");
      const state = callback.searchParams.get("state");
      if (!code || state !== transaction.state) throw new AuthFlowError("state_mismatch");
      if (this.now() - transaction.createdAt > AUTH_TRANSACTION_TTL_MS) {
        throw new AuthFlowError("expired");
      }
      const payload = await this.requestTokens(new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        code,
        code_verifier: transaction.codeVerifier,
        redirect_uri: transaction.redirectUri,
      }));
      const session = this.sessionFromTokenResponse(payload, transaction.nonce);
      await this.dependencies.store.saveSession(session);
      return session;
    } finally {
      await this.dependencies.store.clearTransaction();
    }
  }

  private async requestTokens(body: URLSearchParams): Promise<TokenResponse> {
    const config = this.requireConfig();
    let response: Response;
    try {
      response = await this.fetcher(config.tokenEndpoint, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch {
      throw new AuthFlowError("network");
    }
    let payload: TokenResponse;
    try {
      payload = await response.json() as TokenResponse;
    } catch {
      throw new AuthFlowError("invalid_token");
    }
    if (!response.ok) throw new AuthFlowError("network");
    return payload;
  }

  private sessionFromTokenResponse(payload: TokenResponse, nonce?: string, previous?: AuthSession): AuthSession {
    const config = this.requireConfig();
    if (
      typeof payload.access_token !== "string" ||
      (previous === undefined && typeof payload.id_token !== "string") ||
      (payload.token_type !== undefined &&
        (typeof payload.token_type !== "string" || payload.token_type.toLowerCase() !== "bearer"))
    ) {
      throw new AuthFlowError("invalid_token");
    }
    const now = this.now();
    const accessClaims = decodeJwt(payload.access_token);
    validateClaims(accessClaims, config.issuer, config.audience, now);
    const idToken = typeof payload.id_token === "string" ? payload.id_token : previous?.idToken;
    if (idToken === undefined) throw new AuthFlowError("invalid_token");
    let user = previous?.user;
    if (typeof payload.id_token === "string") {
      const identityClaims = decodeJwt(payload.id_token);
      validateClaims(identityClaims, config.issuer, config.clientId, now, nonce);
      user = userFromClaims(identityClaims, config);
      if (identityClaims.sub !== accessClaims.sub) throw new AuthFlowError("invalid_token");
    }
    if (user === undefined) throw new AuthFlowError("invalid_token");
    const jwtExpiry = Number(accessClaims.exp) * 1_000;
    const responseExpiry = typeof payload.expires_in === "number" && payload.expires_in > 0
      ? now + payload.expires_in * 1_000
      : jwtExpiry;
    return {
      version: 1,
      accessToken: payload.access_token,
      idToken,
      refreshToken: typeof payload.refresh_token === "string"
        ? payload.refresh_token
        : previous?.refreshToken ?? null,
      expiresAt: Math.min(jwtExpiry, responseExpiry),
      user,
    };
  }

  async getValidAccessToken(): Promise<string> {
    const session = await this.dependencies.store.readSession();
    if (session === null) throw new AuthFlowError("reauth_required");
    if (session.expiresAt - this.now() > REFRESH_SKEW_MS) return session.accessToken;
    if (session.refreshToken === null) {
      await this.dependencies.store.clearAll();
      throw new AuthFlowError("reauth_required");
    }
    try {
      const payload = await this.requestTokens(new URLSearchParams({
        grant_type: "refresh_token",
        client_id: this.requireConfig().clientId,
        refresh_token: session.refreshToken,
      }));
      const refreshed = this.sessionFromTokenResponse(payload, undefined, session);
      await this.dependencies.store.saveSession(refreshed);
      return refreshed.accessToken;
    } catch (error: unknown) {
      await this.dependencies.store.clearAll();
      if (error instanceof AuthFlowError) throw error;
      throw new AuthFlowError("reauth_required");
    }
  }

  async logout(): Promise<AuthPublicState> {
    const config = this.dependencies.config;
    const session = await this.dependencies.store.readSession();
    await this.dependencies.store.clearAll();
    const token = session?.refreshToken ?? session?.accessToken;
    if (config?.revocationEndpoint && token) {
      try {
        await this.fetcher(config.revocationEndpoint, {
          method: "POST",
          headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token, client_id: config.clientId }).toString(),
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          referrerPolicy: "no-referrer",
        });
      } catch {
        // Local credentials are already cleared; provider revocation is best effort.
      }
    }
    return config === null ? { status: "not_configured" } : { status: "signed_out" };
  }
}
