import type { Page } from "@playwright/test";

import type { AnalysisResponse } from "../../src/types/analysis";
import type { AnalysisResponseV3 } from "../../src/types/generated/api-v3";
import type {
  BrandRecordV4,
  SecurityAdminAuditEventV4,
  SecurityAppealRecordV4,
  SecurityConversationV4,
  SecurityReportAdminRecordV4,
  SecurityReportRecordV4,
  SecurityScopeResponseV4,
} from "../../src/types/generated/api-v4";

export const ANALYSIS_ID = "10000000-0000-4000-8000-000000000001";
export const FOLLOW_UP_ANALYSIS_ID = "10000000-0000-4000-8000-000000000009";
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
  const followUp = {
    ...completed,
    analysis_id: FOLLOW_UP_ANALYSIS_ID,
    conversation_version: 2,
    explanation: "Follow-up xác nhận người gửi tiếp tục yêu cầu thông tin đăng nhập.",
  } satisfies SecurityScopeResponseV4;
  let conversationVersion = 1;
  let reports: SecurityReportRecordV4[] = [];
  let appeals: SecurityAppealRecordV4[] = [];
  const conversation: SecurityConversationV4 = {
    contract_version: "v4",
    conversation_id: completed.conversation_id,
    status: "active",
    active_analysis_id: completed.analysis_id,
    summary: {
      security_context: completed.security_context,
      evidence_refs: completed.explanation_evidence_refs,
    },
    context_version: completed.conversation_version,
    created_at: now,
    updated_at: now,
    expires_at: "2026-09-12T08:00:00Z",
  };

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
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}/reports`, async (route) => {
    if (route.request().method() === "POST") {
      const payload = route.request().postDataJSON() as { reason: string; comment?: string | null };
      reports = [{
        contract_version: "v4", report_id: "70000000-0000-4000-8000-000000000007",
        analysis_id: ANALYSIS_ID, reason: payload.reason, comment: payload.comment ?? null,
        status: "submitted", decision: null, reviewer_id: null, review_note: null,
        created_at: now, reviewed_at: null,
      }];
      return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(reports[0]) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(reports) });
  });
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}/appeals`, async (route) => {
    if (route.request().method() === "POST") {
      const payload = route.request().postDataJSON() as { reason: string; comment?: string | null };
      appeals = [{
        contract_version: "v4", appeal_id: "80000000-0000-4000-8000-000000000008",
        analysis_id: ANALYSIS_ID, reason: payload.reason, comment: payload.comment ?? null,
        status: "submitted", outcome: null, resolution_note: null, reviewer_id: null,
        created_at: now, resolved_at: null,
      }];
      return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(appeals[0]) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(appeals) });
  });
  await page.route(`**/api/v4/analyses/${FOLLOW_UP_ANALYSIS_ID}/reports`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v4/analyses/${FOLLOW_UP_ANALYSIS_ID}/appeals`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v4/conversations/${completed.conversation_id}`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ ...conversation, context_version: conversationVersion, active_analysis_id: conversationVersion === 1 ? ANALYSIS_ID : FOLLOW_UP_ANALYSIS_ID }),
  }));
  await page.route("**/api/v4/analyses/page*", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ contract_version: "v4", items: [completed], total: 1, limit: 10, offset: 0 }),
  }));
  await page.route(`**/api/v4/analyses/${ANALYSIS_ID}`, (route) => {
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(completed) });
  });
  await page.route(`**/api/v4/analyses/${FOLLOW_UP_ANALYSIS_ID}/events*`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ contract_version: "v4", events: [], next_cursor: null }),
  }));
  await page.route(`**/api/v4/analyses/${FOLLOW_UP_ANALYSIS_ID}`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(followUp),
  }));
  await page.route("**/api/v4/analyses", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([completed]) });
    }
    const payload = route.request().postDataJSON() as { conversation_id?: string };
    if (payload.conversation_id) {
      conversationVersion = 2;
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(followUp) });
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(running) });
  });
}

export async function installAdminReviewFlow(page: Page) {
  let reviewed = false;
  let v4ReportReviewed = false;
  const v3 = completedAnalysis();
  const review: AnalysisResponse = { ...v3, contract_version: "v2" };
  const campaignId = "50000000-0000-4000-8000-000000000005";
  const domainIntelligence = {
    domain: "tapdoanx-qua.example", analysis_count: 4, report_count: 1,
    risk_distribution: { MALICIOUS: 4 }, threat_distribution: { PROMOTION_PRIZE_SCAM: 4 },
    first_seen_at: v3.created_at, last_seen_at: v3.completed_at, evidence_refs: ["evidence:domain"],
  };
  const threatIntelligence = {
    threat_type: "PROMOTION_PRIZE_SCAM", analysis_count: 4, report_count: 1,
    risk_distribution: { MALICIOUS: 4 }, domains: ["tapdoanx-qua.example"],
    first_seen_at: v3.created_at, last_seen_at: v3.completed_at, evidence_refs: ["evidence:threat"],
  };
  const campaign = {
    contract_version: "v4", campaign_id: campaignId, hypothesis: "Shared prize lure and credential path",
    analysis_ids: [ANALYSIS_ID, "10000000-0000-4000-8000-000000000002", "10000000-0000-4000-8000-000000000003"],
    window_started_at: v3.created_at, window_ended_at: v3.completed_at,
    aggregate_signals: { "domain:tapdoanx-qua.example": 3, "pattern:credential_path": 3 },
    reviewer_status: "confirmed", clustering_version: "security-clustering-v1",
    evidence_refs: ["evidence:campaign"], reviewer_id: "admin-e2e", review_note: "Verified aggregate signals",
    reviewed_at: v3.completed_at, created_at: v3.created_at,
  };
  const adminCase: SecurityScopeResponseV4 = {
    contract_version: "v4", analysis_id: ANALYSIS_ID,
    conversation_id: "11000000-0000-4000-8000-000000000001", conversation_version: 1,
    status: "completed", scope_decision: "IN_SCOPE", terminal: true, next_step: "END",
    scope_reasons: ["url_present", "credential_request"],
    security_context: {
      schema_version: "security-context-v1", claimed_entity: "Tập đoàn X", scenario: "promotion_prize",
      requested_action: "open_link", amount: null, urgency: true, urls: [DANGEROUS_URL],
      credential_request: true, otp_request: false, payment_request: false,
      personal_information_request: false, impersonation_signals: ["brand_name_in_message"],
      potential_threat: "PROMOTION_PRIZE_SCAM",
    },
    follow_up_question: null, boundary_message: null,
    limitations: ["External provider evidence was unavailable."], investigation_status: "partial",
    investigation_plan: [{ step_id: "step-admin-review", tool: "local_url_rules", target: DANGEROUS_URL, reason_code: "url_present", depends_on: [], status: "completed", status_reason: null }],
    evidence: [{ evidence_ref: "evidence:admin-review", type: "local_url_rule", source: "local-url-rules", target: DANGEROUS_URL, signal: "credential_path", description: "Credential path observed.", observed_at: v3.created_at, confidence: 0.94, provenance_ref: "ruleset:security-url-v1" }],
    errors: [], tool_calls_used: 0, risk: "MALICIOUS", score: 95, confidence: 0.94,
    threat_type: "PROMOTION_PRIZE_SCAM", policy_version: "security-risk-v1",
    recommended_actions: ["DO_NOT_OPEN_LINK", "REPORT_AND_BLOCK_SENDER"],
    explanation: "Credential lure conflicts with the claimed promotion.",
    explanation_evidence_refs: ["evidence:admin-review"], created_at: v3.created_at, completed_at: v3.completed_at,
  };
  const adminReport: SecurityReportAdminRecordV4 = {
    contract_version: "v4", report_id: "70000000-0000-4000-8000-000000000007",
    analysis_id: ANALYSIS_ID, owner_id: "user-e2e", reason: "Kết luận cần human review",
    comment: "Please inspect the evidence chain.", status: "submitted", decision: null,
    reviewer_id: null, review_note: null, created_at: v3.created_at, reviewed_at: null,
  };
  const brand: BrandRecordV4 = {
    brand_id: "90000000-0000-4000-8000-000000000009", name: "Tập đoàn X",
    aliases: ["Tap doan X"], official_domains: ["tapdoanx.example"], official_contacts: ["1900-0000"],
    provenance: "Verified corporate registry", policy_version: "brand-registry-v1",
    effective_from: v3.created_at, effective_until: null, lifecycle: "active",
    reviewer_id: "admin-e2e", created_at: v3.created_at,
  };
  const auditEvent: SecurityAdminAuditEventV4 = {
    audit_id: "91000000-0000-4000-8000-000000000009", resource_type: "brand",
    resource_id: brand.brand_id, action: "brand_created", actor_id: "admin-e2e",
    note: "Verified corporate registry", occurred_at: v3.created_at, evidence_refs: ["registry:tapdoanx"],
  };

  await page.route("**/api/v2/admin/cases", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(reviewed ? [] : [review]) }));
  await page.route("**/api/v2/admin/blacklist", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(reviewed ? [{ domain: "tapdoanx-qua.example", decision_id: "40000000-0000-4000-8000-000000000001", added_at: v3.completed_at }] : []) }));
  await page.route("**/api/v3/admin/review-queue", (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }));
  await page.route(`**/api/v2/admin/cases/${ANALYSIS_ID}/decision`, async (route) => {
    const payload = route.request().postDataJSON() as { note?: string; action?: string };
    if (!payload.note || payload.action !== "add_to_blacklist") return route.fulfill({ status: 422, contentType: "application/json", body: JSON.stringify({ error: { code: "VALIDATION_ERROR", message: "invalid decision", retryable: false, details: {} } }) });
    reviewed = true;
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ decision_id: "40000000-0000-4000-8000-000000000001", analysis_id: ANALYSIS_ID, case_status: "approved", reviewed_at: v3.completed_at }) });
  });
  await page.route("**/api/v4/admin/intelligence/domains*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [domainIntelligence], total: 1, limit: 10, offset: 0 }) }));
  await page.route("**/api/v4/admin/intelligence/threats*", (route) => {
    const limit = Number(new URL(route.request().url()).searchParams.get("limit") ?? 10);
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [threatIntelligence], total: 1, limit, offset: 0 }) });
  });
  await page.route("**/api/v4/admin/security-memory/page*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [], total: 4, limit: 1, offset: 0 }) }));
  await page.route(`**/api/v4/admin/security-campaigns/${campaignId}/audit`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([{ audit_id: "60000000-0000-4000-8000-000000000006", campaign_id: campaignId, previous_status: "pending_review", status: "confirmed", reviewer_id: "admin-e2e", note: "Verified aggregate signals", occurred_at: v3.completed_at, clustering_version: "security-clustering-v1", evidence_refs: ["evidence:campaign"] }]) }));
  await page.route(`**/api/v4/admin/security-campaigns/${campaignId}`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(campaign) }));
  await page.route("**/api/v4/admin/security-campaigns/page*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [campaign], total: 1, limit: 10, offset: 0 }) }));
  await page.route("**/api/v4/capabilities", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", product_profile: "security_triage_vnext", release_profile: "pre_cutover", conversation_resume: true, admin_feedback_review: true, intelligence_explorer: true, unified_v4_audit: true, admin_action_contract: "v3", executable_admin_actions: ["add_to_blacklist"], deferred_admin_actions: ["block_domain", "publish_broad_warning"], compatibility_contracts: ["v2", "v3", "v4"] }) }));
  await page.route("**/api/v4/admin/reports*", async (route) => {
    const items = v4ReportReviewed ? [] : [adminReport];
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items, total: items.length, limit: 10, offset: 0 }) });
  });
  await page.route("**/api/v4/admin/reports/*/decision", async (route) => {
    v4ReportReviewed = true;
    const payload = route.request().postDataJSON() as { decision: "approved" | "rejected" | "dismissed"; note: string };
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...adminReport, status: "processed", decision: payload.decision, reviewer_id: "admin-e2e", review_note: payload.note, reviewed_at: v3.completed_at }) });
  });
  await page.route(`**/api/v4/admin/analyses/${ANALYSIS_ID}`, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(adminCase) }));
  await page.route("**/api/v4/admin/brands/page*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [brand], total: 1, limit: 10, offset: 0 }) }));
  await page.route("**/api/v4/admin/audit*", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ contract_version: "v4", items: [auditEvent], total: 1, limit: 20, offset: 0 }) }));
}
