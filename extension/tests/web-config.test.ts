import { describe, expect, it } from "vitest";

import { buildCaseUrl, resolveWebConfig } from "../src/web/config";

const analysisId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";

describe("Phase 7 fixed web handoff", () => {
  it("is disabled without an exact configured web origin", () => {
    expect(resolveWebConfig({})).toBeNull();
  });

  it("creates only the fixed owner-scoped case route", () => {
    const config = resolveWebConfig({ VITE_TRUSTGUARD_WEB_URL: "http://localhost:3000/" });
    expect(config).toEqual({ baseUrl: "http://localhost:3000" });
    expect(buildCaseUrl(config!, analysisId)).toBe(`http://localhost:3000/cases/${analysisId}`);
  });

  it.each([
    "https://web.example/cases",
    "https://user:secret@web.example",
    "https://*.example",
    "http://web.example",
  ])("rejects an unsafe web origin %s", (value) => {
    expect(() => resolveWebConfig({ VITE_TRUSTGUARD_WEB_URL: value })).toThrow();
  });

  it("rejects invalid analysis IDs instead of creating an arbitrary target", () => {
    expect(() => buildCaseUrl(
      { baseUrl: "https://trustguard.example" },
      "../../login?returnTo=https://evil.example",
    )).toThrow();
  });
});
