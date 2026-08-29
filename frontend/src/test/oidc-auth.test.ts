import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  completeOidcAuthorization,
  createOidcAuthorizationRequest,
  getStoredAccessToken,
  restoreOidcSession,
  saveOidcSession,
  type OidcSession,
} from "@/lib/auth/oidc";

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: object) => btoa(JSON.stringify(value))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode(payload)}.signature`;
}

function configureOidc() {
  vi.stubEnv("NEXT_PUBLIC_OIDC_ISSUER", "https://identity.example/");
  vi.stubEnv("NEXT_PUBLIC_OIDC_CLIENT_ID", "frontend-client");
  vi.stubEnv("NEXT_PUBLIC_OIDC_AUDIENCE", "https://api.example");
  vi.stubEnv("NEXT_PUBLIC_OIDC_ROLES_CLAIM", "roles");
  vi.stubEnv("NEXT_PUBLIC_OIDC_ADMIN_ROLE", "security_admin");
}

describe("OIDC Authorization Code + PKCE", () => {
  beforeEach(() => {
    configureOidc();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  afterEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("creates a state-bound PKCE authorization request", async () => {
    const authorizationUrl = new URL(await createOidcAuthorizationRequest("/history"));
    const transaction = JSON.parse(
      window.sessionStorage.getItem("ai_protect_oidc_transaction") ?? "{}",
    ) as Record<string, unknown>;

    expect(authorizationUrl.origin + authorizationUrl.pathname).toBe("https://identity.example/authorize");
    expect(authorizationUrl.searchParams.get("response_type")).toBe("code");
    expect(authorizationUrl.searchParams.get("client_id")).toBe("frontend-client");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authorizationUrl.searchParams.get("state")).toBe(transaction.state);
    expect(transaction).toMatchObject({ returnTo: "/history" });
    expect(transaction.codeVerifier).not.toBe(authorizationUrl.searchParams.get("code_challenge"));
  });

  it("opens Universal Login in signup mode without changing the PKCE flow", async () => {
    const authorizationUrl = new URL(
      await createOidcAuthorizationRequest("/", { screenHint: "signup" }),
    );

    expect(authorizationUrl.searchParams.get("screen_hint")).toBe("signup");
    expect(authorizationUrl.searchParams.get("response_type")).toBe("code");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("rejects a callback with the wrong state before contacting the token endpoint", async () => {
    await createOidcAuthorizationRequest("/");
    const fetcher = vi.fn();

    await expect(completeOidcAuthorization("?code=code-1&state=wrong", fetcher))
      .rejects.toThrow("state");
    expect(fetcher).not.toHaveBeenCalled();
    expect(window.sessionStorage.getItem("ai_protect_oidc_transaction")).toBeNull();
  });

  it("does not expose an identity-provider error description", async () => {
    await expect(completeOidcAuthorization("?error=access_denied&error_description=tenant-secret"))
      .rejects.toThrow("Đăng nhập bị từ chối hoặc đã hết hạn. Vui lòng thử lại.");
  });

  it("exchanges the code, validates identity claims and stores an admin session per tab", async () => {
    const requestUrl = new URL(await createOidcAuthorizationRequest("/admin/review"));
    const transaction = JSON.parse(
      window.sessionStorage.getItem("ai_protect_oidc_transaction") ?? "{}",
    ) as { nonce: string; codeVerifier: string };
    window.localStorage.setItem("ai_protect_access_token", "legacy-token");
    window.localStorage.setItem("ai_protect_user", JSON.stringify({ role: "security_admin" }));
    const idToken = jwt({
      iss: "https://identity.example/",
      aud: "frontend-client",
      sub: "oidc-user-1",
      name: "Security Reviewer",
      email: "reviewer@example.com",
      "https://api.example/roles": ["security_admin"],
      nonce: transaction.nonce,
      exp: Math.floor(Date.now() / 1000) + 600,
    });
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: "signed-access-token",
      id_token: idToken,
      refresh_token: "rotating-refresh-token",
      expires_in: 600,
      token_type: "Bearer",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    const result = await completeOidcAuthorization(
      `?code=authorization-code&state=${requestUrl.searchParams.get("state")}`,
      fetcher,
    );

    expect(result.returnTo).toBe("/admin/review");
    expect(result.session.user).toEqual({
      id: "oidc-user-1",
      name: "Security Reviewer",
      email: "reviewer@example.com",
      role: "security_admin",
    });
    expect(getStoredAccessToken()).toBe("signed-access-token");
    expect(window.localStorage.getItem("ai_protect_access_token")).toBeNull();
    expect(window.localStorage.getItem("ai_protect_user")).toBeNull();
    expect(fetcher).toHaveBeenCalledWith("https://identity.example/oauth/token", expect.objectContaining({
      method: "POST",
      body: expect.stringContaining(`code_verifier=${encodeURIComponent(transaction.codeVerifier)}`),
    }));
  });

  it("rotates an expiring access token during session bootstrap", async () => {
    const session: OidcSession = {
      accessToken: "expired-token",
      idToken: "existing-id-token",
      refreshToken: "refresh-token",
      expiresAt: Date.now() - 1,
      user: { id: "user-1", name: "User", email: "user@example.com", role: "user" },
    };
    saveOidcSession(session);
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: "refreshed-access-token",
      refresh_token: "next-refresh-token",
      expires_in: 600,
      token_type: "Bearer",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    const restored = await restoreOidcSession(fetcher);

    expect(restored).toMatchObject({
      accessToken: "refreshed-access-token",
      refreshToken: "next-refresh-token",
      user: session.user,
    });
    expect(getStoredAccessToken()).toBe("refreshed-access-token");
  });
});
