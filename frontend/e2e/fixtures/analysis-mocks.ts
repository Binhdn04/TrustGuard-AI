import type { Page } from "@playwright/test";

import type { AnalysisResponse } from "../../src/types/analysis";
import type { AnalysisEventV3, AnalysisResponseV3 } from "../../src/types/generated/api-v3";

export const ANALYSIS_ID = "10000000-0000-4000-8000-000000000001";
export const DANGEROUS_URL = "https://tapdoanx-qua.example/login";

function completedAnalysis(overrides: Partial<AnalysisResponseV3> = {}): AnalysisResponseV3 {
  const now = "2026-08-08T06:00:00Z";
  return {
    contract_version: "v3",
    analysis_id: ANALYSIS_ID,
    status: "completed",
    input_type: "text_with_url",
    normalized_urls: [DANGEROUS_URL],
    claims: ["Thông báo nhận quà yêu cầu đăng nhập là đáng tin cậy."],
    investigation_plan: [
      { step_id: "local", tool: "local_rules", target: "message", reason_code: "input_validation", depends_on: [], status: "completed" },
      { step_id: "claim", tool: "claim_retriever", target: "claim", reason_code: "claim_verification", depends_on: ["local"], status: "completed" },
      { step_id: "blacklist", tool: "blacklist_lookup", target: DANGEROUS_URL, reason_code: "url_present", depends_on: ["local"], status: "completed" },
    ],
    risk_score: 95,
    risk_level: "critical",
    verdict: "malicious",
    recommended_action: "escalate_for_review",
    confidence: 0.94,
    summary: "Nguồn fact-check bác bỏ nội dung và URL trùng danh sách chặn đã duyệt.",
    reasons: ["Nội dung mạo danh chương trình tặng quà."],
    evidence: [
      { type: "fact_check", source: "Fixture Fact Check", title: "Cảnh báo giả mạo", url: "https://factcheck.example/canh-bao", finding: "False", observed_at: now },
      { type: "blacklist", source: "approved-blacklist", title: "Blacklist hit", url: null, finding: "Domain trùng danh sách chặn đã duyệt.", observed_at: now },
    ],
    limitations: ["Kết quả chỉ phản ánh bằng chứng có tại thời điểm kiểm tra."],
    case_status: "pending_review",
    scoring_version: "risk-v2",
    created_at: now,
    completed_at: now,
    ...overrides,
  };
}

export async function installUserAnalysisFlow(page: Page) {
  let detailReads = 0;
  const completed = completedAnalysis();

  await page.route("**/api/v3/ws-tickets", (route) => route.fulfill({
    status: 501,
    contentType: "application/json",
    body: JSON.stringify({ error: { code: "NOT_IMPLEMENTED", message: "stream unavailable", retryable: false, details: {} } }),
  }));
  await page.route(`**/api/v3/analyses/${ANALYSIS_ID}/events*`, (route) => {
    const cursor = new URL(route.request().url()).searchParams.get("cursor");
    const events: AnalysisEventV3[] = cursor
      ? [{ event_id: "20000000-0000-4000-8000-000000000004", analysis_id: ANALYSIS_ID, sequence: 4, event_type: "final_result", occurred_at: completed.completed_at!, payload: { result_ref: `analysis:${ANALYSIS_ID}:result`, status: "completed" } }]
      : [
          { event_id: "20000000-0000-4000-8000-000000000001", analysis_id: ANALYSIS_ID, sequence: 1, event_type: "analysis_status", occurred_at: completed.created_at, payload: { status: "running" } },
          { event_id: "20000000-0000-4000-8000-000000000002", analysis_id: ANALYSIS_ID, sequence: 2, event_type: "provisional_warning", occurred_at: completed.created_at, payload: { risk_level: "critical", summary: "URL trùng tín hiệu rủi ro cục bộ.", evidence_refs: ["local-rule:1"], is_provisional: true } },
          { event_id: "20000000-0000-4000-8000-000000000003", analysis_id: ANALYSIS_ID, sequence: 3, event_type: "step_transition", occurred_at: completed.created_at, payload: { step_id: "claim", tool: "claim_retriever", target: "claim", reason_code: "claim_verification", depends_on: ["local"], status: "running" } },
        ];
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v3", events, next_cursor: cursor ? "4" : "3" }) });
  });
  await page.route(`**/api/v3/analyses/${ANALYSIS_ID}/reports`, (route) => route.fulfill({
    status: 201,
    contentType: "application/json",
    body: JSON.stringify({ contract_version: "v3", report_id: "30000000-0000-4000-8000-000000000001", analysis_id: ANALYSIS_ID, created_at: completed.completed_at }),
  }));
  await page.route(`**/api/v3/analyses/${ANALYSIS_ID}`, (route) => {
    detailReads += 1;
    const response = detailReads >= 2
      ? completed
      : { ...completed, status: "running", risk_score: null, risk_level: null, verdict: null, recommended_action: null, confidence: null, summary: null, reasons: null, evidence: null, limitations: null, completed_at: null };
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
  });
  await page.route("**/api/v3/analyses", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([completed]) });
    }
    return route.fulfill({ status: 202, contentType: "application/json", body: JSON.stringify({ contract_version: "v3", analysis_id: ANALYSIS_ID, status: "queued", created_at: completed.created_at }) });
  });
}

export async function installAdminReviewFlow(page: Page) {
  let reviewed = false;
  const v3 = completedAnalysis();
  const review: AnalysisResponse = { ...v3, contract_version: "v2" };

  await page.route("**/api/v2/admin/cases", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(reviewed ? [] : [review]) }));
  await page.route("**/api/v2/admin/blacklist", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(reviewed ? [{ domain: "tapdoanx-qua.example", decision_id: "40000000-0000-4000-8000-000000000001", added_at: v3.completed_at }] : []) }));
  await page.route("**/api/v3/admin/review-queue", (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v2/admin/cases/${ANALYSIS_ID}/decision`, async (route) => {
    const payload = route.request().postDataJSON() as { note?: string; action?: string };
    if (!payload.note || payload.action !== "add_to_blacklist") return route.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ error: { code: "VALIDATION_ERROR", message: "invalid decision", retryable: false, details: {} } }) });
    reviewed = true;
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ decision_id: "40000000-0000-4000-8000-000000000001", analysis_id: ANALYSIS_ID, case_status: "approved", reviewed_at: v3.completed_at }) });
  });
}
