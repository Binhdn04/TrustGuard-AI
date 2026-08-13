import type { Page } from "@playwright/test";

import type { AnalysisResponse } from "../../src/types/analysis";
import type { AnalysisResponseV3 } from "../../src/types/generated/api-v3";
import type { SecurityScopeResponseV4 } from "../../src/types/generated/api-v4";

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
  const now = "2026-08-13T08:00:00Z";
  const completed: SecurityScopeResponseV4 = {
    contract_version: "v4", analysis_id: ANALYSIS_ID,
    conversation_id: "11000000-0000-4000-8000-000000000001", conversation_version: 1,
    status: "completed", scope_decision: "IN_SCOPE", terminal: true, next_step: "END",
    scope_reasons: ["promotion_prize_context", "url_present"],
    security_context: {
      schema_version: "security-context-v1", claimed_entity: null, scenario: "promotion_prize",
      requested_action: "open_link", amount: null, urgency: false, urls: [DANGEROUS_URL],
      credential_request: true, otp_request: false, payment_request: false,
      personal_information_request: false, impersonation_signals: [], potential_threat: "PROMOTION_PRIZE_SCAM",
    },
    follow_up_question: null, boundary_message: null,
    limitations: ["Kết quả phản ánh bằng chứng tại thời điểm kiểm tra."],
    investigation_status: "completed",
    investigation_plan: [{ step_id: "step-aaaaaaaaaaaa", tool: "local_url_rules", target: DANGEROUS_URL, reason_code: "url_present", depends_on: [], status: "completed", status_reason: null }],
    evidence: [{ evidence_ref: "evidence:aaaaaaaaaaaaaaaa", type: "local_url_rule", source: "local-url-rules", target: DANGEROUS_URL, signal: "credential_path", description: "URL quà tặng yêu cầu đăng nhập.", observed_at: now, confidence: 0.9, provenance_ref: null }],
    errors: [], tool_calls_used: 0, risk: "MALICIOUS", score: 95, confidence: 0.94,
    threat_type: "PROMOTION_PRIZE_SCAM", policy_version: "security-risk-v1",
    recommended_actions: ["DO_NOT_OPEN_LINK", "REPORT_AND_BLOCK_SENDER"],
    explanation: "Liên kết có tín hiệu giả mạo chương trình trúng thưởng và yêu cầu đăng nhập.",
    explanation_evidence_refs: ["evidence:aaaaaaaaaaaaaaaa"], created_at: now, completed_at: now,
  };
  const running = { ...completed, status: "running" as const, terminal: false, next_step: "RISK_ASSESSMENT" as const, completed_at: null };

  await page.route("**/api/v4/ws-tickets", (route) => route.fulfill({
    status: 501,
    contentType: "application/json",
    body: JSON.stringify({ error: { code: "NOT_IMPLEMENTED", message: "stream unavailable", retryable: false, details: {} } }),
  }));
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}/events*`, (route) => {
    const cursor = new URL(route.request().url()).searchParams.get("cursor");
    const events = [{ event_id: cursor ? "20000000-0000-4000-8000-000000000003" : "20000000-0000-4000-8000-000000000002", analysis_id: ANALYSIS_ID, sequence: cursor ? 3 : 2, status: cursor ? "completed" : "running", step: cursor ? "completed" : "investigation", occurred_at: now }];
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", events, next_cursor: cursor ? "Mw" : "Mg" }) });
  });
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}/reports`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}/appeals`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}`, (route) => {
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(completed) });
  });
  await page.route("**/api/v4/analyses", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([completed]) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(running) });
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
