import { describe, expect, it, vi } from "vitest";

import type { OidcConfig } from "../src/auth/config";
import { AuthFlowError, OidcAuthManager } from "../src/auth/oidc";
import {
  AUTH_SESSION_STORAGE_KEY,
  AUTH_TRANSACTION_STORAGE_KEY,
  AuthSessionStore,
  type AuthSessionStorageArea,
} from "../src/auth/session-store";

const NOW = 2_000_000_000_000;
const REDIRECT_URI = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/oidc";
const config: OidcConfig = {
  issuer: "https://identity.example",
  clientId: "extension-public-client",
  audience: "https://api.example",
  authorizationEndpoint: "https://identity.example/authorize",
  tokenEndpoint: "https://identity.example/oauth/token",
  revocationEndpoint: "https://identity.example/oauth/revoke",
  rolesClaim: "https://api.example/roles",
  adminRole: "security_admin",
  scope: "openid profile email offline_access",
};

class MemoryStorage implements AuthSessionStorageArea {
  readonly values: Record<string, unknown> = {};

  get(key: string): Promise<Record<string, unknown>> {
    return Promise.resolve({ [key]: this.values[key] });
  }

  set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, items);
    return Promise.resolve();
  }

  remove(keys: string | string[]): Promise<void> {
    for (const key of Array.isArray(keys) ? keys : [keys]) delete this.values[key];
    return Promise.resolve();
  }
}

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: object): string => btoa(JSON.stringify(value))
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/u, "");
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode(payload)}.signature`;
}

function requestBody(init: RequestInit): string {
  if (typeof init.body !== "string") throw new Error("Expected URL-encoded request body.");
  return init.body;
}

function tokenResponse(nonce: string, overrides: { access?: Record<string, unknown>; id?: Record<string, unknown> } = {}): Response {
  const common = {
    iss: "https://identity.example/",
    sub: "user-1",
    exp: NOW / 1_000 + 600,
  };
  return new Response(JSON.stringify({
    access_token: jwt({ ...common, aud: "https://api.example", ...overrides.access }),
    id_token: jwt({
      ...common,
      aud: "extension-public-client",
      nonce,
      name: "TrustGuard User",
      email: "user@example.test",
      ...overrides.id,
    }),
    refresh_token: "rotating-refresh-token",
    expires_in: 600,
    token_type: "Bearer",
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

function manager(storage: MemoryStorage, fetcher = vi.fn()) {
  const identity = {
    getRedirectURL: vi.fn(() => REDIRECT_URI),
    launchWebAuthFlow: vi.fn<() => Promise<string | undefined>>(),
  };
  const auth = new OidcAuthManager({
    config,
    store: new AuthSessionStore(storage),
    identity,
    fetcher,
    now: () => NOW,
    randomValue: (bytes = 32) => (bytes === 64 ? "v".repeat(86) : "r".repeat(43)),
    codeChallenge: () => Promise.resolve("challenge-value"),
  });
  return { auth, identity, fetcher };
}

async function preparedFlow(storage: MemoryStorage, fetcher = vi.fn()) {
  const setup = manager(storage, fetcher);
  const authorizationUrl = new URL(await setup.auth.beginAuthorization());
  const transaction = await new AuthSessionStore(storage).readTransaction();
  if (transaction === null) throw new Error("Expected stored transaction.");
  return { ...setup, authorizationUrl, transaction };
}

describe("extension OIDC Authorization Code + PKCE", () => {
  it("builds an exact redirect, state, nonce and S256 public-client request", async () => {
    const { authorizationUrl, transaction } = await preparedFlow(new MemoryStorage());

    expect(authorizationUrl.origin + authorizationUrl.pathname).toBe("https://identity.example/authorize");
    expect(authorizationUrl.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(authorizationUrl.searchParams.get("client_id")).toBe(config.clientId);
    expect(authorizationUrl.searchParams.get("audience")).toBe(config.audience);
    expect(authorizationUrl.searchParams.get("state")).toBe(transaction.state);
    expect(authorizationUrl.searchParams.get("nonce")).toBe(transaction.nonce);
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl.searchParams.has("client_secret")).toBe(false);
  });

  it("rejects state mismatch before token exchange and clears terminal auth state", async () => {
    const storage = new MemoryStorage();
    const fetcher = vi.fn();
    const { auth, identity } = manager(storage, fetcher);
    identity.launchWebAuthFlow.mockResolvedValue(`${REDIRECT_URI}?code=code-1&state=wrong`);

    await expect(auth.login()).rejects.toMatchObject({ code: "state_mismatch" });
    expect(fetcher).not.toHaveBeenCalled();
    expect(storage.values).not.toHaveProperty(AUTH_TRANSACTION_STORAGE_KEY);
    expect(storage.values).not.toHaveProperty(AUTH_SESSION_STORAGE_KEY);
  });

  it("rejects an unexpected redirect before token exchange", async () => {
    const storage = new MemoryStorage();
    const fetcher = vi.fn();
    const { auth, identity } = manager(storage, fetcher);
    identity.launchWebAuthFlow.mockResolvedValue("https://attacker.chromiumapp.org/oidc?code=x&state=x");

    await expect(auth.login()).rejects.toMatchObject({ code: "redirect_mismatch" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    `${REDIRECT_URI}?code=first&code=second&state=${"r".repeat(43)}`,
    `${REDIRECT_URI}?code=first&state=${"r".repeat(43)}&state=second`,
    `https://user:pass@abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/oidc?code=first&state=${"r".repeat(43)}`,
  ])("rejects ambiguous or credential-bearing callbacks before token exchange", async (callback) => {
    const storage = new MemoryStorage();
    const fetcher = vi.fn();
    const { auth, identity } = manager(storage, fetcher);
    identity.launchWebAuthFlow.mockResolvedValue(callback);

    await expect(auth.login()).rejects.toBeInstanceOf(AuthFlowError);
    expect(fetcher).not.toHaveBeenCalled();
    expect(storage.values).not.toHaveProperty(AUTH_TRANSACTION_STORAGE_KEY);
    expect(storage.values).not.toHaveProperty(AUTH_SESSION_STORAGE_KEY);
  });

  it("clears the transaction when the user cancels the identity window", async () => {
    const storage = new MemoryStorage();
    const { auth, identity } = manager(storage);
    identity.launchWebAuthFlow.mockResolvedValue(undefined);

    await expect(auth.login()).rejects.toEqual(new AuthFlowError("canceled"));
    expect(storage.values).not.toHaveProperty(AUTH_TRANSACTION_STORAGE_KEY);
  });

  it("survives a service-worker restart between authorization and callback", async () => {
    const storage = new MemoryStorage();
    const initial = await preparedFlow(storage);
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(tokenResponse(initial.transaction.nonce)));
    const restarted = manager(storage, fetcher);

    const session = await restarted.auth.completeAuthorization(
      `${REDIRECT_URI}?code=authorization-code&state=${initial.transaction.state}`,
    );

    expect(session.user).toMatchObject({ id: "user-1", name: "TrustGuard User" });
    expect(storage.values).toHaveProperty(AUTH_SESSION_STORAGE_KEY);
    expect(storage.values).not.toHaveProperty(AUTH_TRANSACTION_STORAGE_KEY);
    expect(fetcher).toHaveBeenCalled();
    const tokenCall = fetcher.mock.calls[0] as unknown as [RequestInfo | URL, RequestInit];
    expect(tokenCall[0]).toBe(config.tokenEndpoint);
    expect(tokenCall[1]).toMatchObject({
      method: "POST",
      redirect: "error",
      credentials: "omit",
    });
    const body = requestBody(tokenCall[1]);
    expect(body).toContain(`code_verifier=${"v".repeat(86)}`);
    expect(body).not.toContain("client_secret");
  });

  it.each([
    { access: { exp: NOW / 1_000 - 1 }, expected: "expired" },
    { access: { aud: "https://wrong-api.example" }, expected: "invalid_token" },
    { id: { aud: "wrong-extension-client" }, expected: "invalid_token" },
    { id: { nonce: "wrong-nonce" }, expected: "invalid_token" },
  ])("rejects expired or wrong-audience tokens %#", async ({ access, id, expected }) => {
    const storage = new MemoryStorage();
    const initial = await preparedFlow(storage);
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(tokenResponse(initial.transaction.nonce, { access, id })));
    const restarted = manager(storage, fetcher);

    await expect(restarted.auth.completeAuthorization(
      `${REDIRECT_URI}?code=authorization-code&state=${initial.transaction.state}`,
    )).rejects.toMatchObject({ code: expected });
    expect(storage.values).not.toHaveProperty(AUTH_SESSION_STORAGE_KEY);
  });

  it("refreshes before API use and revokes the rotating token on logout", async () => {
    const storage = new MemoryStorage();
    const store = new AuthSessionStore(storage);
    await store.saveSession({
      version: 1,
      accessToken: "expired-access-token",
      idToken: "existing-id-token",
      refreshToken: "old-refresh-token",
      expiresAt: NOW - 1,
      user: { id: "user-1", name: "User", email: "user@example.test", role: "user" },
    });
    const refreshedAccess = jwt({
      iss: "https://identity.example/",
      aud: "https://api.example",
      sub: "user-1",
      exp: NOW / 1_000 + 600,
    });
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: refreshedAccess,
        refresh_token: "next-refresh-token",
        expires_in: 600,
        token_type: "Bearer",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }));
    const { auth } = manager(storage, fetcher);

    await expect(auth.getValidAccessToken()).resolves.toBe(refreshedAccess);
    await expect(auth.logout()).resolves.toEqual({ status: "signed_out" });
    expect(storage.values).not.toHaveProperty(AUTH_SESSION_STORAGE_KEY);
    const revokeCall = fetcher.mock.calls.at(-1) as unknown as [RequestInfo | URL, RequestInit];
    expect(revokeCall[0]).toBe(config.revocationEndpoint);
    expect(revokeCall[1]).toMatchObject({
      credentials: "omit",
      redirect: "error",
    });
    expect(requestBody(revokeCall[1])).toContain("token=next-refresh-token");
  });
});
