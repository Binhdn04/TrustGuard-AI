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

  it("supports events and user report receipts", async () => {
    const api = new MockAnalysisApi();
    const accepted = await api.createAnalysis({
      message: "https://official.example/security",
      consent_to_scan_urls: true,
    });

    const events = await api.getAnalysisEvents(accepted.analysis_id);
    const receipt = await api.reportAnalysis(accepted.analysis_id, {
      reason: "Kết quả đánh giá chưa chính xác",
    });

    expect(events.map((event) => event.status)).toEqual(["queued", "completed"]);
    expect(receipt.analysis_id).toBe(accepted.analysis_id);
    expect(receipt.report_id).toBeTruthy();
    expect((await api.listAdminReports())[0].reason).toBeTruthy();
  });

  it("exposes admin decisions and blacklist entries", async () => {
    const api = new MockAnalysisApi();
    const accepted = await api.createAnalysis({
      message: "https://tapdoanx-qua.example/login",
      consent_to_scan_urls: true,
    });

    await api.decideAdminCase(accepted.analysis_id, {
      decision: "approved",
      action: "add_to_blacklist",
      note: "Evidence reviewed",
    });

    expect((await api.listAdminDecisions())[0].analysis_id).toBe(
      accepted.analysis_id,
    );
    expect((await api.listAdminBlacklist())[0].domain).toBe(
      "tapdoanx-qua.example",
    );
  });
});
