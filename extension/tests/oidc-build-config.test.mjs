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

  it("rejects wildcard, cross-origin and non-local HTTP endpoints", () => {
    const base = {
      VITE_OIDC_ISSUER: "https://identity.example/",
      VITE_OIDC_CLIENT_ID: "extension-public-client",
      VITE_OIDC_AUDIENCE: "https://api.example",
    };
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "https://*.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "https://evil.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_TOKEN_ENDPOINT: "http://identity.example/token" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_CLIENT_SECRET: "never-bundle-this" })).toThrow();
    expect(() => resolveOidcBuildPolicy({ ...base, VITE_OIDC_SCOPE: "profile email" })).toThrow();
  });
});
