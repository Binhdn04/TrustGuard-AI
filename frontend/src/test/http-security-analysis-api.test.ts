import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpSecurityAnalysisApi } from "@/lib/api/http-security-analysis-api";

describe("HttpSecurityAnalysisApi", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses only v4 endpoints and sends per-turn consent and conversation version", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({}), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test", () => "owner-token");
    await api.createAnalysis({
      message: "Họ yêu cầu OTP",
      consent: { external_url_lookup: false, official_source_lookup: true },
      conversation_id: "conversation-1",
      conversation_version: 2,
    });

    expect(fetchMock).toHaveBeenCalledWith("http://backend.test/api/v4/analyses", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({ Authorization: "Bearer owner-token" }),
      body: JSON.stringify({
        message: "Họ yêu cầu OTP",
        consent: { external_url_lookup: false, official_source_lookup: true },
        conversation_id: "conversation-1",
        conversation_version: 2,
      }),
    }));
  });

  it("uses v4 report and appeal boundaries", async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify([]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    vi.stubGlobal("fetch", fetchMock);
    const api = new HttpSecurityAnalysisApi("http://backend.test");
    await api.listReports("analysis-1");
    await api.listAnalysisAppeals("analysis-1");

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "http://backend.test/api/v4/analyses/analysis-1/reports",
      "http://backend.test/api/v4/analyses/analysis-1/appeals",
    ]);
  });
});
