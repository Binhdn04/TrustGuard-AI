import { describe, expect, it } from "vitest";

import { resolveOidcBuildPolicy } from "../scripts/oidc-build-config.mjs";

describe("OIDC manifest build policy", () => {
  it("keeps network closed when local auth is not configured", () => {
    expect(resolveOidcBuildPolicy({})).toEqual({
      configured: false,
      connectSource: "'none'",
      hostPermissions: undefined,
    });
  });

  it("emits only the exact configured token origin", () => {
    expect(resolveOidcBuildPolicy({
      VITE_OIDC_ISSUER: "https://identity.example/",
      VITE_OIDC_CLIENT_ID: "extension-public-client",
      VITE_OIDC_AUDIENCE: "https://api.example",
      VITE_OIDC_TOKEN_ENDPOINT: "https://identity.example/oauth/token",
      VITE_OIDC_REVOCATION_ENDPOINT: "https://identity.example/oauth/revoke",
    })).toEqual({
      configured: true,
      connectSource: "https://identity.example",
      hostPermissions: ["https://identity.example/*"],
    });
  });

  it("adds only the exact TrustGuard API origin and deduplicates origins", () => {
    expect(resolveOidcBuildPolicy({
      VITE_TRUSTGUARD_API_URL: "http://localhost:8000/",
    })).toEqual({
      configured: true,
      connectSource: "http://localhost:8000 ws://localhost:8000",
      hostPermissions: ["http://localhost:8000/*"],
    });
    expect(resolveOidcBuildPolicy({
      VITE_TRUSTGUARD_API_URL: "https://api.example",
      VITE_OIDC_ISSUER: "https://api.example/",
      VITE_OIDC_CLIENT_ID: "extension-public-client",
      VITE_OIDC_AUDIENCE: "https://api.example",
    })).toMatchObject({
      connectSource: "https://api.example wss://api.example",
      hostPermissions: ["https://api.example/*"],
    });
  });

  it("rejects wildcard, cross-origin and non-local HTTP endpoints", () => {
    const base = {
      VITE_OIDC_ISSUER: "https://identity.example/",
      VITE_OIDC_CLIENT_ID: "extension-public-client",
      VITE_OIDC_AUDIENCE: "https://api.example",
    };
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "https://*.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "https://evil.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "http://identity.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_ISSUER: "https://*.example" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "https://identity.example/token?secret=x" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_CLIENT_SECRET: "never-bundle-this" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_SCOPE: "profile email" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ VITE_TRUSTGUARD_API_URL: "https://*.example" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ VITE_TRUSTGUARD_API_URL: "https://api.example/api/v4" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ VITE_TRUSTGUARD_API_URL: "http://api.example" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ VITE_TRUSTGUARD_WEB_URL: "https://web.example/cases" })).toThrow();
  });

  it("validates the web handoff origin without granting it API network permission", () => {
    expect(resolveOidcBuildPolicy({
      VITE_TRUSTGUARD_WEB_URL: "http://localhost:3000",
    })).toEqual({
      configured: false,
      connectSource: "'none'",
      hostPermissions: undefined,
    });
  });
});
