import { describe, expect, it } from "vitest";

import type { AnalysisSnapshot } from "../src/api/client";
import { finalResultView } from "../src/analysis/final-result";

const analysisId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";
const createdAt = "2026-08-29T10:00:00.000Z";

function snapshot(overrides: Partial<AnalysisSnapshot> = {}): AnalysisSnapshot {
  return {
    analysisId,
    status: "completed",
    terminal: true,
    createdAt,
    result: {
      scopeDecision: "IN_SCOPE",
      risk: "HIGH_RISK",
      score: 86,
      confidence: 0.914,
      summary: "Có dấu hiệu yêu cầu thông tin nhạy cảm.",
      followUpQuestion: null,
      boundaryMessage: null,
      limitations: [],
      recommendedActions: ["DO_NOT_SHARE_OTP", "VERIFY_VIA_OFFICIAL_CHANNEL"],
      degraded: false,
    },
    ...overrides,
  };
}

describe("Phase 7 authoritative final presentation", () => {
  it("maps in-scope risk and actions only from the final snapshot", () => {
    expect(finalResultView(snapshot())).toEqual({
      analysisId,
      title: "Kết quả kiểm tra bảo mật",
      scopeLabel: "Trong phạm vi Security Triage",
      riskLabel: "Rủi ro cao",
      tone: "danger",
      score: 86,
      confidencePercent: 91,
      summary: "Có dấu hiệu yêu cầu thông tin nhạy cảm.",
      actions: ["Không cung cấp mã OTP", "Xác minh qua kênh chính thức"],
      limitations: [],
      degraded: false,
      failed: false,
    });
  });

  it("keeps hostile backend text as inert presentation data", () => {
    const payload = `<img src=x onerror=alert(1)><script>location='https://evil.example'</script>`;
    expect(finalResultView(snapshot({
      result: { ...snapshot().result!, summary: payload },
    }))).toMatchObject({ summary: payload });
  });

  it("renders NEED_MORE_INFO without carrying a risk or action forward", () => {
    const view = finalResultView(snapshot({
      result: {
        ...snapshot().result!,
        scopeDecision: "NEED_MORE_INFO",
        followUpQuestion: "Bạn đã mở liên kết hoặc cung cấp thông tin gì chưa?",
      },
    }));
    expect(view).toMatchObject({
      title: "Cần thêm thông tin",
      riskLabel: null,
      score: null,
      confidencePercent: null,
      summary: "Bạn đã mở liên kết hoặc cung cấp thông tin gì chưa?",
      actions: [],
      tone: "neutral",
    });
  });

  it("renders out-of-scope and insufficient-evidence states distinctly", () => {
    expect(finalResultView(snapshot({
      result: {
        ...snapshot().result!,
        scopeDecision: "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
        boundaryMessage: "TrustGuard chỉ xử lý yêu cầu an toàn tin nhắn và liên kết.",
      },
    }))).toMatchObject({
      title: "Ngoài phạm vi Security Triage",
      riskLabel: null,
      actions: [],
    });
    expect(finalResultView(snapshot({
      result: { ...snapshot().result!, risk: "INSUFFICIENT_EVIDENCE" },
    }))).toMatchObject({
      riskLabel: "Chưa đủ bằng chứng",
      tone: "caution",
    });
  });

  it("never turns a failed analysis or non-terminal response into a risk verdict", () => {
    expect(finalResultView(snapshot({ status: "failed" }))).toMatchObject({
      title: "Không thể hoàn tất phân tích",
      riskLabel: null,
      actions: [],
      failed: true,
    });
    expect(finalResultView(snapshot({ status: "running", terminal: false, result: null }))).toBeNull();
  });
});
