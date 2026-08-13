import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AnalysisWorkspace } from "@/components/analysis/analysis-workspace";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

function response(overrides: Partial<SecurityScopeResponseV4> = {}): SecurityScopeResponseV4 {
  return {
    contract_version: "v4",
    analysis_id: crypto.randomUUID(),
    conversation_id: "10000000-0000-4000-8000-000000000001",
    conversation_version: 1,
    status: "completed",
    scope_decision: "NEED_MORE_INFO",
    terminal: true,
    next_step: "END",
    scope_reasons: ["security_concern_missing_context"],
    security_context: null,
    follow_up_question: "Họ yêu cầu bạn làm gì?",
    boundary_message: null,
    limitations: [],
    investigation_status: "not_started",
    investigation_plan: [],
    evidence: [],
    errors: [],
    tool_calls_used: 0,
    risk: null,
    score: null,
    confidence: null,
    threat_type: null,
    policy_version: null,
    recommended_actions: [],
    explanation: null,
    explanation_evidence_refs: [],
    created_at: "2026-08-13T08:00:00Z",
    completed_at: "2026-08-13T08:00:01Z",
    ...overrides,
  };
}

function apiWith(createAnalysis: SecurityAnalysisApi["createAnalysis"]): SecurityAnalysisApi {
  return {
    createAnalysis,
    getAnalysis: vi.fn(),
    listAnalyses: vi.fn().mockResolvedValue([]),
    getAnalysisEvents: vi.fn().mockResolvedValue({ contract_version: "v4", events: [], next_cursor: null }),
    createWebSocketTicket: vi.fn(),
    reportAnalysis: vi.fn(),
    listReports: vi.fn().mockResolvedValue([]),
    createAppeal: vi.fn(),
    listAnalysisAppeals: vi.fn().mockResolvedValue([]),
    listBrands: vi.fn().mockResolvedValue([]),
    listWhitelist: vi.fn().mockResolvedValue([]),
  };
}

describe("Security Chat workspace", () => {
  it("continues NEED_MORE_INFO with the owner conversation version and fresh consent", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce(response())
      .mockResolvedValueOnce(response({ conversation_version: 2, follow_up_question: "Bạn có URL không?" }));
    render(<AnalysisWorkspace api={apiWith(create)} />);

    fireEvent.change(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), { target: { value: "Tin nhắn này đáng ngờ" } });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    await screen.findByLabelText("Họ yêu cầu bạn làm gì?");

    fireEvent.change(screen.getByLabelText("Họ yêu cầu bạn làm gì?"), { target: { value: "Họ yêu cầu gửi OTP" } });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[1][0]).toEqual(expect.objectContaining({
      conversation_id: "10000000-0000-4000-8000-000000000001",
      conversation_version: 1,
      consent: { external_url_lookup: false, official_source_lookup: false },
    }));
  });

  it("renders out-of-scope separately from a security conclusion", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response({
      scope_decision: "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
      follow_up_question: null,
      boundary_message: "Chỉ đánh giá rủi ro bảo mật.",
      scope_reasons: ["general_fact_check_news"],
    })));
    render(<AnalysisWorkspace api={api} />);
    fireEvent.change(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), { target: { value: "Tin tức này đúng không?" } });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByText(/nằm ngoài phạm vi Security Triage/i)).toBeInTheDocument();
    expect(screen.queryByText(/Nên làm ngay/i)).not.toBeInTheDocument();
  });

  it("renders a completed security risk without claim or screenshot semantics", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response({
      scope_decision: "IN_SCOPE",
      scope_reasons: ["otp_request"],
      security_context: {
        schema_version: "security-context-v1", claimed_entity: "ngân hàng", scenario: "account_verification",
        requested_action: "share_otp", amount: null, urgency: true, urls: [], credential_request: false,
        otp_request: true, payment_request: false, personal_information_request: false,
        impersonation_signals: ["claimed_organization"], potential_threat: "CREDENTIAL_THEFT",
      },
      follow_up_question: null,
      risk: "MALICIOUS",
      score: 98,
      confidence: 0.98,
      threat_type: "CREDENTIAL_THEFT",
      policy_version: "security-risk-v1",
      recommended_actions: ["DO_NOT_SHARE_OTP", "REPORT_AND_BLOCK_SENDER"],
      explanation: "Yêu cầu OTP có bằng chứng đe dọa đã xác nhận.",
    })));
    render(<AnalysisWorkspace api={api} />);
    fireEvent.change(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), { target: { value: "Ngân hàng yêu cầu OTP" } });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("heading", { name: "Nguy hiểm" })).toBeInTheDocument();
    expect(screen.getByText("Không chia sẻ mã OTP")).toBeInTheDocument();
    expect(screen.queryByText(/tuyên bố|fact-check|ảnh trang web/i)).not.toBeInTheDocument();
  });

  it("submits reports and appeals through the v4 owner boundary", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response({
      scope_decision: "IN_SCOPE", scope_reasons: ["otp_request"], follow_up_question: null,
      security_context: {
        schema_version: "security-context-v1", claimed_entity: null, scenario: "unknown",
        requested_action: "share_otp", amount: null, urgency: false, urls: [], credential_request: false,
        otp_request: true, payment_request: false, personal_information_request: false,
        impersonation_signals: [], potential_threat: "CREDENTIAL_THEFT",
      },
      risk: "HIGH_RISK", score: 85, confidence: 0.8, threat_type: "CREDENTIAL_THEFT",
      policy_version: "security-risk-v1", recommended_actions: ["DO_NOT_SHARE_OTP"],
      explanation: "Yêu cầu OTP có rủi ro cao.",
    })));
    vi.mocked(api.reportAnalysis).mockResolvedValue({
      contract_version: "v4", report_id: "report-1", analysis_id: "analysis-1",
      reason: "Cần xem lại", comment: null, status: "submitted", created_at: "2026-08-13T08:00:00Z",
    });
    vi.mocked(api.createAppeal).mockResolvedValue({
      contract_version: "v4", appeal_id: "appeal-1", analysis_id: "analysis-1",
      reason: "Bằng chứng chưa phù hợp", comment: null, status: "submitted", outcome: null,
      resolution_note: null, created_at: "2026-08-13T08:00:00Z", resolved_at: null,
    });
    render(<AnalysisWorkspace api={api} />);
    fireEvent.change(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), { target: { value: "Tin nhắn yêu cầu OTP" } });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    fireEvent.click(await screen.findByRole("button", { name: "Gửi báo cáo" }));
    await waitFor(() => expect(api.reportAnalysis).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: /Yêu cầu xem xét lại quyết định/i }));
    fireEvent.change(screen.getByLabelText("Lý do khiếu nại"), { target: { value: "Bằng chứng chưa phù hợp" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi khiếu nại" }));
    await waitFor(() => expect(api.createAppeal).toHaveBeenCalled());
  });
});
