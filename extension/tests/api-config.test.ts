import { describe, expect, it } from "vitest";

import { buildWebSocketStreamUrl, resolveApiConfig } from "../src/api/config";

describe("TrustGuard API runtime configuration", () => {
  it("is fail-closed when no API origin is configured", () => {
    expect(resolveApiConfig({})).toBeNull();
  });

  it("normalizes an exact local or HTTPS API origin", () => {
    expect(resolveApiConfig({ VITE_TRUSTGUARD_API_URL: "http://localhost:8000/" })).toEqual({
      baseUrl: "http://localhost:8000",
    });
    expect(resolveApiConfig({ VITE_TRUSTGUARD_API_URL: "https://api.example" })).toEqual({
      baseUrl: "https://api.example",
    });
  });

  it.each([
    "*",
    "https://*.example",
    "https://user:secret@api.example",
    "https://api.example/api/v4",
    "https://api.example?token=private",
    "https://api.example#private",
    "http://api.example",
  ])("rejects a non-exact or insecure API URL %s", (value) => {
    expect(() => resolveApiConfig({ VITE_TRUSTGUARD_API_URL: value })).toThrow();
  });

  it("builds only the exact analysis stream URL with a single-use ticket", () => {
    expect(buildWebSocketStreamUrl(
      { baseUrl: "http://localhost:8000" },
      "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e",
      "/api/v4/analyses/4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e/stream",
      "short-lived-ticket",
      "MQ",
    )).toBe(
      "ws://localhost:8000/api/v4/analyses/4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e/stream?ticket=short-lived-ticket&cursor=MQ",
    );
    expect(() => buildWebSocketStreamUrl(
      { baseUrl: "https://api.example" },
      "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e",
      "https://evil.example/api/v4/analyses/4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e/stream",
      "ticket",
      null,
    )).toThrow();
  });
});
