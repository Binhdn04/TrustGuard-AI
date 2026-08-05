import { beforeEach, describe, expect, it } from "vitest";

import {
  MockAnalysisApi,
  resetMockAnalyses,
} from "@/lib/api/mock-analysis-api";

describe("MockAnalysisApi", () => {
  beforeEach(() => resetMockAnalyses());

  it("follows queued, running and completed contract states", async () => {
    const api = new MockAnalysisApi();
    const accepted = await api.createAnalysis({
      message: "Nhận quà tại https://tapdoanx-qua.example/login",
      consent_to_scan_urls: true,
    });

    expect(accepted.status).toBe("queued");
    expect((await api.getAnalysis(accepted.analysis_id)).status).toBe("running");

    const completed = await api.getAnalysis(accepted.analysis_id);
    expect(completed.status).toBe("completed");
    expect(completed.risk_level).toBe("critical");
    expect(completed.case_status).toBe("pending_review");
  });

  it("does not treat missing consent as a safe result", async () => {
    const api = new MockAnalysisApi();
    const accepted = await api.createAnalysis({
      message: "https://unknown.example/login",
      consent_to_scan_urls: false,
    });
    await api.getAnalysis(accepted.analysis_id);
    const completed = await api.getAnalysis(accepted.analysis_id);

    expect(completed.verdict).toBe("inconclusive");
    expect(completed.limitations).toContain(
      "Bạn chưa cho phép quét URL qua dịch vụ bên ngoài.",
    );
  });
});
