import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpAnalysisApi } from "@/lib/api/http-analysis-api";

describe("HttpAnalysisApi", () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
  });

  it("sends the demo user bearer token to the analysis API", async () => {
    window.localStorage.setItem(
      "ai_protect_user",
      JSON.stringify({ role: "user" }),
    );
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi("http://backend.test").listAnalyses();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/analyses",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer dev-user-token",
        }),
      }),
    );
  });

  it("uses the admin token for review queue requests", async () => {
    window.localStorage.setItem(
      "ai_protect_user",
      JSON.stringify({ role: "security_admin" }),
    );
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi("http://backend.test").listAdminCases();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/admin/cases",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer dev-admin-token",
        }),
      }),
    );
  });

  it.each(["reports", "decisions", "blacklist"])(
    "loads admin %s from the backend",
    async (resource) => {
      window.localStorage.setItem(
        "ai_protect_user",
        JSON.stringify({ role: "security_admin" }),
      );
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
      vi.stubGlobal("fetch", fetchMock);

      const api = new HttpAnalysisApi("http://backend.test");
      if (resource === "reports") await api.listAdminReports();
      if (resource === "decisions") await api.listAdminDecisions();
      if (resource === "blacklist") await api.listAdminBlacklist();

      expect(fetchMock).toHaveBeenCalledWith(
        `http://backend.test/api/v1/admin/${resource}`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer dev-admin-token",
          }),
        }),
      );
    },
  );

  it("posts user reports to the analysis report endpoint", async () => {
    const receipt = {
      report_id: "report-1",
      analysis_id: "analysis-1",
      created_at: "2026-08-06T08:00:00Z",
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(receipt), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi("http://backend.test").reportAnalysis(
      "analysis-1",
      { reason: "Evidence không phù hợp", comment: "Cần kiểm tra lại." },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v1/analyses/analysis-1/reports",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          reason: "Evidence không phù hợp",
          comment: "Cần kiểm tra lại.",
        }),
      }),
    );
  });
});
