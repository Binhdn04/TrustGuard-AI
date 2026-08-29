import { describe, expect, it } from "vitest";

import { resolveOidcConfig } from "../src/auth/config";

const validEnvironment = {
  VITE_OIDC_ISSUER: "https://identity.example/",
  VITE_OIDC_CLIENT_ID: "extension-public-client",
  VITE_OIDC_AUDIENCE: "https://api.example",
  VITE_OIDC_REVOCATION_ENDPOINT: "https://identity.example/oauth/revoke",
};

describe("extension OIDC configuration", () => {
  it("is fail-closed but buildable when local OIDC is not configured", () => {
    expect(resolveOidcConfig({})).toBeNull();
    expect(() => resolveOidcConfig({ VITE_OIDC_CLIENT_ID: "partial" })).toThrow("configured together");
  });

  it("derives exact same-origin endpoints for a public client", () => {
    expect(resolveOidcConfig(validEnvironment)).toEqual(expect.objectContaining({
      issuer: "https://identity.example",
      clientId: "extension-public-client",
      authorizationEndpoint: "https://identity.example/authorize",
      tokenEndpoint: "https://identity.example/oauth/token",
      revocationEndpoint: "https://identity.example/oauth/revoke",
    }));
  });

  it.each([
    { ...validEnvironment, VITE_OIDC_TOKEN_ENDPOINT: "https://evil.example/token" },
    { ...validEnvironment, VITE_OIDC_ISSUER: "http://identity.example" },
    { ...validEnvironment, VITE_OIDC_TOKEN_ENDPOINT: "https://user:pass@identity.example/token" },
    { ...validEnvironment, VITE_OIDC_SCOPE: "profile email" },
  ])("rejects unsafe or incomplete config %#", (environment) => {
    expect(() => resolveOidcConfig(environment)).toThrow();
  });
});
