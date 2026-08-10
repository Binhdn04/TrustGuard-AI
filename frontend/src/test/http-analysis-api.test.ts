import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { HttpAnalysisApi } from "@/lib/api/http-analysis-api";

describe("HttpAnalysisApi", () => {
  beforeEach(() => {
    vi.stubEnv("NEXT_PUBLIC_DEMO_USER_TOKEN", "dev-user-token");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ADMIN_TOKEN", "dev-admin-token");
  });

  afterEach(() => {
    window.localStorage.clear();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("does not derive API credentials from the editable local user profile", async () => {
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

    await new HttpAnalysisApi(
      "http://backend.test",
      () => window.localStorage.getItem("ai_protect_access_token"),
    ).listAnalyses();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v3/analyses",
      expect.objectContaining({
        credentials: "include",
        headers: { Accept: "application/json" },
      }),
    );
  });

  it("uses a credential supplied by the authentication layer", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi(
      "http://backend.test",
      () => "signed-access-token",
    ).listAdminCases();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v2/admin/cases",
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer signed-access-token",
        }),
      }),
    );
  });

  it("prefers the OIDC access token over local demo credentials", async () => {
    window.localStorage.setItem("ai_protect_access_token", "oidc-access-token");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi(
      "http://backend.test",
      () => window.localStorage.getItem("ai_protect_access_token"),
    ).listAnalyses();

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v3/analyses",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer oidc-access-token" }),
      }),
    );
  });

  it("creates a short-lived WebSocket ticket", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        contract_version: "v3",
        ticket: "ticket-1",
        analysis_id: "analysis-1",
        expires_at: "2026-08-08T08:00:00Z",
        stream_path: "/api/v3/analyses/analysis-1/stream",
        single_use: true,
      }), { status: 201, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi("http://backend.test").createWebSocketTicket("analysis-1");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v3/ws-tickets",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ analysis_id: "analysis-1" }) }),
    );
  });

  it("posts an admin decision through the compatible endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        decision_id: "decision-1",
        analysis_id: "analysis-1",
        case_status: "approved",
        reviewed_at: "2026-08-08T08:00:00Z",
      }), { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new HttpAnalysisApi("http://backend.test").decideAdminCase("analysis-1", {
      decision: "approved",
      action: "add_to_blacklist",
      note: "Evidence checked.",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/v2/admin/cases/analysis-1/decision",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it.each(["reports", "decisions", "blacklist"])(
    "loads admin %s from the backend",
    async (resource) => {
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
        `http://backend.test/api/v2/admin/${resource}`,
        expect.objectContaining({
          credentials: "include",
          headers: { Accept: "application/json" },
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
      "http://backend.test/api/v3/analyses/analysis-1/reports",
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
