import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpSecurityAnalysisApi } from "@/lib/api/http-security-analysis-api";

function ok(payload: unknown = {}) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("HttpSecurityAnalysisApi", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses only v4 endpoints and sends per-turn consent and conversation version", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(ok()));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test", () => "owner-token");
    await api.createAnalysis({
      message: "Họ yêu cầu OTP",
      consent: { external_url_lookup: false },
      conversation_id: "conversation-1",
      conversation_version: 2,
    });

    expect(fetchMock).toHaveBeenCalledWith("http://backend.test/api/v4/analyses", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({ Authorization: "Bearer owner-token" }),
      body: JSON.stringify({
        message: "Họ yêu cầu OTP",
        consent: { external_url_lookup: false },
        conversation_id: "conversation-1",
        conversation_version: 2,
      }),
    }));
  });

  it("uses v4 report and appeal boundaries", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(ok([])));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test");
    await api.listReports("analysis-1");
    await api.listAnalysisAppeals("analysis-1");

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "http://backend.test/api/v4/analyses/analysis-1/reports",
      "http://backend.test/api/v4/analyses/analysis-1/appeals",
    ]);
  });

  it("sends the active conversation reference for contextual chat", async () => {
    const fetchMock = vi.fn().mockResolvedValue(ok({
      contract_version: "v4",
      route: "conversation",
      response: "Hướng dẫn tiếp nối.",
    }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test", () => "owner-token");

    await api.chat("Nếu tôi đã mở link thì sao?", {
      conversationId: "conversation-1",
      conversationVersion: 3,
    });

    expect(fetchMock).toHaveBeenCalledWith("http://backend.test/api/v4/chat", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({
        message: "Nếu tôi đã mở link thì sao?",
        conversation_id: "conversation-1",
        conversation_version: 3,
      }),
    }));
  });

  it("requests a non-persistent page capture with fresh URL consent", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(new Blob(["jpeg"]), {
      status: 200,
      headers: { "Content-Type": "image/jpeg" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test", () => "owner-token");

    const image = await api.capturePage("analysis/id", 2);

    expect(image.type).toBe("image/jpeg");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v4/analyses/analysis%2Fid/page-capture",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        headers: expect.objectContaining({
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        }),
        body: JSON.stringify({ url_index: 2, external_url_lookup: true }),
      }),
    );
  });

  it("uses the bounded admin analysis-detail endpoint", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(ok()));
    vi.stubGlobal("fetch", fetchMock);

    await new HttpSecurityAnalysisApi("http://backend.test", () => "admin-token")
      .getAdminAnalysis("analysis/id");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v4/admin/analyses/analysis%2Fid",
      expect.objectContaining({ credentials: "include", headers: expect.objectContaining({ Authorization: "Bearer admin-token" }) }),
    );
  });

  it("encodes WP9A page filters and keeps credentials plus auth on GET requests", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(ok()));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test/", () => " admin-token ");

    await api.getCapabilities();
    await api.pageAnalyses({
      scope_decision: "IN_SCOPE",
      risk: "HIGH_RISK",
      threat_type: "PHISHING",
      q: "ACME bank",
      limit: 25,
      offset: 50,
    });
    await api.pageSecurityMemory({ q: "login.example", verdict: "malicious", limit: 10 });
    await api.listAdminAudit({ resource_type: "campaign", action: "reviewed", offset: 5 });

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "http://backend.test/api/v4/capabilities",
      "http://backend.test/api/v4/analyses/page?scope_decision=IN_SCOPE&risk=HIGH_RISK&threat_type=PHISHING&q=ACME+bank&limit=25&offset=50",
      "http://backend.test/api/v4/admin/security-memory/page?q=login.example&verdict=malicious&limit=10",
      "http://backend.test/api/v4/admin/audit?resource_type=campaign&action=reviewed&offset=5",
    ]);
    for (const [, options] of fetchMock.mock.calls) {
      expect(options).toEqual(expect.objectContaining({
        credentials: "include",
        headers: expect.objectContaining({ Authorization: "Bearer admin-token" }),
      }));
    }
  });

  it("uses the WP9A admin mutation endpoints and JSON bodies", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(ok()));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test", () => "admin-token");

    await api.createBrand({
      name: "ACME",
      official_domains: ["acme.test"],
      provenance: "Verified registry",
      effective_from: "2026-08-13T00:00:00Z",
    });
    await api.createBrandVersion("brand/id", {
      name: "ACME v2",
      official_domains: ["acme.test"],
      provenance: "Reviewed update",
      effective_from: "2026-08-14T00:00:00Z",
    });
    await api.disableBrand("brand/id");
    await api.correctSecurityMemory("memory/id", { verdict: "false_positive", note: "Reviewed" });
    await api.reviewSecurityCampaign("campaign/id", { decision: "confirmed", note: "Correlated" });
    await api.decideAdminReport("report/id", { decision: "approved", note: "Confirmed" });
    await api.decideAdminAppeal("appeal/id", { outcome: "overturn", note: "New evidence" });

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "http://backend.test/api/v4/admin/brands",
      "http://backend.test/api/v4/admin/brands/brand%2Fid/versions",
      "http://backend.test/api/v4/admin/brands/brand%2Fid/disable",
      "http://backend.test/api/v4/admin/security-memory/memory%2Fid/corrections",
      "http://backend.test/api/v4/admin/security-campaigns/campaign%2Fid/decision",
      "http://backend.test/api/v4/admin/reports/report%2Fid/decision",
      "http://backend.test/api/v4/admin/appeals/appeal%2Fid/decision",
    ]);
    expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: "POST",
      credentials: "include",
      headers: expect.objectContaining({
        Authorization: "Bearer admin-token",
        "Content-Type": "application/json",
      }),
      body: JSON.stringify({
        name: "ACME",
        official_domains: ["acme.test"],
        provenance: "Verified registry",
        effective_from: "2026-08-13T00:00:00Z",
      }),
    }));
    expect(fetchMock.mock.calls[1][1]).toEqual(expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ name: "ACME v2", official_domains: ["acme.test"], provenance: "Reviewed update", effective_from: "2026-08-14T00:00:00Z" }),
    }));
    expect(fetchMock.mock.calls[2][1]).not.toHaveProperty("body");
  });

  it("preserves the v4 error envelope", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: "FORBIDDEN",
        message: "Admin only",
        retryable: false,
        details: { reason: "role" },
      },
    }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    })));
    const api = new HttpSecurityAnalysisApi("http://backend.test");

    await expect(api.listAdminReports()).rejects.toMatchObject({
      name: "ApiError",
      code: "FORBIDDEN",
      message: "Admin only",
      retryable: false,
      status: 403,
      details: { reason: "role" },
    });
  });

  it("fails clearly when the frontend build has no API URL", async () => {
    const api = new HttpSecurityAnalysisApi("", () => "owner-token");

    await expect(api.getCapabilities()).rejects.toMatchObject({
      name: "ApiError",
      code: "API_CONFIGURATION_ERROR",
      message: expect.stringContaining("NEXT_PUBLIC_API_URL"),
    });
  });

  it("explains a network or CORS failure instead of surfacing the browser error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Request failed")));
    const api = new HttpSecurityAnalysisApi("https://backend.example.test", () => "owner-token");

    await expect(api.getCapabilities()).rejects.toMatchObject({
      name: "ApiError",
      code: "NETWORK_ERROR",
      retryable: true,
      status: 0,
      message: expect.stringContaining("CORS_ORIGINS"),
    });
  });
});
