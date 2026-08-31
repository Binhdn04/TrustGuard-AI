import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AnalysisWorkspace } from "@/components/analysis/analysis-workspace";
import { ApiError } from "@/lib/api/api-error";
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
    getCapabilities: vi.fn(),
    chat: vi.fn().mockResolvedValue({
      contract_version: "v4",
      route: "security_analysis",
      response: "Tôi sẽ mở một lượt kiểm tra bảo mật mới.",
    }),
    createAnalysis,
    getAnalysis: vi.fn(),
    getAdminAnalysis: vi.fn(),
    listAnalyses: vi.fn().mockResolvedValue([]),
    pageAnalyses: vi.fn(),
    getConversation: vi.fn(),
    listConversations: vi.fn(),
    getAnalysisEvents: vi.fn().mockResolvedValue({ contract_version: "v4", events: [], next_cursor: null }),
    createWebSocketTicket: vi.fn(),
    reportAnalysis: vi.fn(),
    listReports: vi.fn().mockResolvedValue([]),
    createAppeal: vi.fn(),
    listAnalysisAppeals: vi.fn().mockResolvedValue([]),
    listAdminReports: vi.fn(),
    decideAdminReport: vi.fn(),
    listAdminAppeals: vi.fn(),
    decideAdminAppeal: vi.fn(),
    createBrand: vi.fn(),
    createBrandVersion: vi.fn(),
    listBrands: vi.fn().mockResolvedValue([]),
    pageBrands: vi.fn(),
    disableBrand: vi.fn(),
    createWhitelist: vi.fn(),
    listWhitelist: vi.fn().mockResolvedValue([]),
    pageWhitelist: vi.fn(),
    disableWhitelist: vi.fn(),
    listSecurityMemory: vi.fn().mockResolvedValue([]),
    pageSecurityMemory: vi.fn(),
    correctSecurityMemory: vi.fn(),
    listSecurityMemoryAudit: vi.fn().mockResolvedValue([]),
    listSecurityCampaigns: vi.fn().mockResolvedValue([]),
    pageSecurityCampaigns: vi.fn(),
    getSecurityCampaign: vi.fn(),
    reviewSecurityCampaign: vi.fn(),
    listSecurityCampaignAudit: vi.fn().mockResolvedValue([]),
    listDomainIntelligence: vi.fn(),
    listThreatIntelligence: vi.fn(),
    listAdminAudit: vi.fn(),
  };
}

function setComposerMessage(composer: HTMLElement, value: string) {
  composer.textContent = value;
  fireEvent.input(composer);
}

describe("Security Chat workspace", () => {
  it("keeps a rich-pasted link in the submitted and rendered conversation turn", async () => {
    const create = vi.fn().mockResolvedValue(response());
    render(<AnalysisWorkspace api={apiWith(create)} />);
    const composer = screen.getByLabelText(/Dán tin nhắn đáng ngờ/i);

    fireEvent.paste(composer, {
      clipboardData: {
        getData: (type: string) => type === "text/html"
          ? '<p>Đăng ký tại <a href="https://forms.example.test/recruitment?id=42">biểu mẫu tuyển dụng</a></p>'
          : "Đăng ký tại biểu mẫu tuyển dụng",
      },
    });
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "Đăng ký tại biểu mẫu tuyển dụng (https://forms.example.test/recruitment?id=42)",
      }),
      undefined,
    ));
    expect(create.mock.calls[0][0]).not.toHaveProperty("execution_mode");
    const link = await screen.findByRole("link", { name: "https://forms.example.test/recruitment?id=42" });
    expect(link).toHaveAttribute("href", "https://forms.example.test/recruitment?id=42");
  });

  it("submits an idempotent async turn only when the backend capability is enabled", async () => {
    const create = vi.fn().mockResolvedValue({
      contract_version: "v4",
      analysis_id: "10000000-0000-4000-8000-000000000099",
      conversation_id: "10000000-0000-4000-8000-000000000001",
      conversation_version: 1,
      status: "queued",
      created_at: "2026-08-13T08:00:00Z",
    });
    const api = apiWith(create);
    vi.mocked(api.getCapabilities).mockResolvedValue({
      contract_version: "v4",
      product_profile: "security_triage_vnext",
      release_profile: "pre_cutover",
      conversation_resume: true,
      admin_feedback_review: true,
      intelligence_explorer: true,
      unified_v4_audit: true,
      admin_action_contract: "v4",
      executable_admin_actions: ["add_to_blacklist"],
      deferred_admin_actions: [],
      security_async_execution: true,
    });
    render(<AnalysisWorkspace api={api} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn yêu cầu OTP");
    expect(screen.queryByText("Cho phép kiểm tra URL bên ngoài")).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /Cho phép đối chiếu nguồn chính thức/i })).not.toBeInTheDocument();
    expect(screen.getByText(/kiểm tra liên kết bằng dịch vụ bảo mật/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(screen.queryByLabelText(/Dán tin nhắn đáng ngờ/i)).not.toBeInTheDocument();
    expect(create.mock.calls[0][0]).toEqual(expect.objectContaining({
      execution_mode: "async",
      consent: { external_url_lookup: true, official_source_lookup: true },
    }));
    expect(create.mock.calls[0][1]).toEqual({ idempotencyKey: expect.any(String) });
  });

  it("moves from intake into a simple chatbot workspace with analyst details on demand", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response()));
    render(<AnalysisWorkspace api={api} />);

    expect(screen.getByRole("heading", { name: "Bạn muốn kiểm tra điều gì?" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Intake & follow-up" })).not.toBeInTheDocument();

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn cần kiểm tra");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("heading", { name: "Trò chuyện với trợ lý" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Kết luận và hướng dẫn" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Tín hiệu và bằng chứng" })).not.toBeInTheDocument();
    expect(screen.getByRole("tablist", { name: "Khu vực trường hợp" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Kết quả" }));
    expect(screen.getByRole("tab", { name: "Kết quả" })).toHaveAttribute("aria-selected", "true");

    fireEvent.click(screen.getByRole("button", { name: "Kỹ thuật" }));
    expect(screen.getByRole("heading", { name: "Tín hiệu và bằng chứng" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Quyết định và bước tiếp theo" })).toBeInTheDocument();
  });

  it("continues NEED_MORE_INFO with the owner conversation version and automatic lookup policy", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce(response())
      .mockResolvedValueOnce(response({ conversation_version: 2, follow_up_question: "Bạn có URL không?" }));
    render(<AnalysisWorkspace api={apiWith(create)} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn này đáng ngờ");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    await screen.findByLabelText("Họ yêu cầu bạn làm gì?");

    setComposerMessage(screen.getByLabelText("Họ yêu cầu bạn làm gì?"), "Họ yêu cầu gửi OTP");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[1][0]).toEqual(expect.objectContaining({
      conversation_id: "10000000-0000-4000-8000-000000000001",
      conversation_version: 1,
      consent: { external_url_lookup: true, official_source_lookup: true },
    }));
  });

  it("keeps the chatbot composer available after a completed check", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce(response({
        scope_decision: "IN_SCOPE",
        terminal: true,
        next_step: "END",
        follow_up_question: null,
        risk: "SUSPICIOUS",
        score: 55,
        confidence: 0.7,
        threat_type: "PHISHING",
        policy_version: "security-risk-v1",
        recommended_actions: ["PROCEED_WITH_CAUTION"],
        explanation: "Cần thận trọng với nội dung này.",
      }))
      .mockResolvedValueOnce(response({ conversation_version: 2 }));
    const api = apiWith(create);
    render(<AnalysisWorkspace api={api} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Kiểm tra nội dung này");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    expect(await screen.findByRole("heading", { name: "Đáng ngờ" })).toBeInTheDocument();

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Nếu tôi đã mở link thì sao?");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(api.chat).toHaveBeenCalledWith("Nếu tôi đã mở link thì sao?", {
      conversationId: "10000000-0000-4000-8000-000000000001",
      conversationVersion: 1,
    });
    expect(create.mock.calls[1][0]).toEqual(expect.objectContaining({
      conversation_id: "10000000-0000-4000-8000-000000000001",
      conversation_version: 1,
      consent: { external_url_lookup: true, official_source_lookup: true },
    }));
  });

  it("answers an ordinary follow-up without opening another security analysis", async () => {
    const create = vi.fn().mockResolvedValue(response({
      scope_decision: "IN_SCOPE",
      terminal: true,
      next_step: "END",
      follow_up_question: null,
      risk: "SUSPICIOUS",
      score: 55,
      confidence: 0.7,
      threat_type: "PHISHING",
      policy_version: "security-risk-v1",
      recommended_actions: ["PROCEED_WITH_CAUTION"],
      explanation: "Cần thận trọng với nội dung này.",
    }));
    const api = apiWith(create);
    const chat = vi.fn().mockResolvedValue({
      contract_version: "v4" as const,
      route: "conversation" as const,
      response: "Không có gì. Nếu có tin nhắn đáng ngờ khác, bạn cứ gửi tiếp nhé.",
    });
    api.chat = chat;
    render(<AnalysisWorkspace api={api} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Kiểm tra nội dung này");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    expect(await screen.findByRole("heading", { name: "Đáng ngờ" })).toBeInTheDocument();

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Cảm ơn bạn");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByText(/Nếu có tin nhắn đáng ngờ khác/i)).toBeInTheDocument();
    expect(chat).toHaveBeenCalledWith("Cảm ơn bạn", {
      conversationId: "10000000-0000-4000-8000-000000000001",
      conversationVersion: 1,
    });
    expect(create).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("heading", { name: "Đáng ngờ" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i)).toBeInTheDocument();
  });

  it("renders out-of-scope separately from a security conclusion", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response({
      scope_decision: "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
      follow_up_question: null,
      boundary_message: "Chỉ đánh giá rủi ro bảo mật.",
      scope_reasons: ["general_fact_check_news"],
    })));
    render(<AnalysisWorkspace api={api} />);
    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin tức này đúng không?");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByText(/nằm ngoài phạm vi Security Triage/i)).toBeInTheDocument();
    expect(screen.queryByText(/Nên làm ngay/i)).not.toBeInTheDocument();
  });

  it("renders a completed security risk without claim semantics", async () => {
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
    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Ngân hàng yêu cầu OTP");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("heading", { name: "Độc hại" })).toBeInTheDocument();
    expect(screen.getByText("Không chia sẻ mã OTP")).toBeInTheDocument();
    expect(screen.queryByText(/tuyên bố|fact-check|ảnh trang web/i)).not.toBeInTheDocument();
  });

  it("renders a grounded assistant answer and keeps suspicious URLs as plain text", async () => {
    const evidenceRef = "evidence:aaaaaaaaaaaaaaaa";
    const api = apiWith(vi.fn().mockResolvedValue(response({
      scope_decision: "IN_SCOPE",
      scope_reasons: ["url_present"],
      security_context: {
        schema_version: "security-context-v1", claimed_entity: "ACME", scenario: "account_verification",
        requested_action: "open_link", amount: null, urgency: true, urls: ["https://danger.example/login"],
        credential_request: true, otp_request: false, payment_request: false,
        personal_information_request: false, impersonation_signals: [], potential_threat: "PHISHING",
      },
      follow_up_question: null,
      evidence: [{
        evidence_ref: evidenceRef, type: "local_url_rule", source: "local-rules",
        target: "https://danger.example/login", signal: "credential_path",
        description: "URL https://danger.example/login yêu cầu thông tin đăng nhập.",
        observed_at: "2026-08-13T08:00:00Z", confidence: 0.9, provenance_ref: "rules:v1",
      }],
      risk: "HIGH_RISK", score: 90, confidence: 0.9, threat_type: "PHISHING",
      policy_version: "security-risk-v1",
      recommended_actions: ["DO_NOT_OPEN_LINK", "CHANGE_PASSWORD_FROM_TRUSTED_DEVICE", "REVOKE_ACTIVE_SESSIONS", "PRESERVE_MESSAGE_FOR_REPORTING"],
      explanation: "Liên kết có tín hiệu lấy cắp tài khoản.",
      explanation_evidence_refs: [evidenceRef],
      assistant_response: {
        summary: "Liên kết này có rủi ro cao.",
        top_reasons: [{ text: "Đường dẫn yêu cầu đăng nhập.", evidence_refs: [evidenceRef] }],
        uncertainties: ["Chưa có reputation provider."],
        immediate_steps: [
          { action: "DO_NOT_OPEN_LINK", policy_ref: "security-risk-v1" },
          { action: "CHANGE_PASSWORD_FROM_TRUSTED_DEVICE", policy_ref: "security-risk-v1" },
          { action: "REVOKE_ACTIVE_SESSIONS", policy_ref: "security-risk-v1" },
          { action: "PRESERVE_MESSAGE_FOR_REPORTING", policy_ref: "security-risk-v1" },
        ],
        follow_up_offer: "Bạn có thể gửi thêm thông tin không nhạy cảm.",
        response_version: "security-assistant-response-v1",
        generation_mode: "ai",
      },
    })));
    api.capturePage = vi.fn().mockRejectedValue(new Error("blocked by destination"));
    vi.mocked(api.getCapabilities).mockResolvedValue({
      contract_version: "v4",
      product_profile: "security_triage_vnext",
      release_profile: "pre_cutover",
      conversation_resume: true,
      admin_feedback_review: true,
      intelligence_explorer: true,
      unified_v4_audit: true,
      admin_action_contract: "v4",
      executable_admin_actions: ["add_to_blacklist"],
      deferred_admin_actions: [],
      security_page_capture: true,
    });
    render(<AnalysisWorkspace api={api} />);
    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Kiểm tra link");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    const assistant = await screen.findByRole("region", { name: "Phản hồi của trợ lý bảo mật" });
    expect(assistant).toHaveTextContent("Liên kết này có rủi ro cao");
    await waitFor(() => expect(api.capturePage).toHaveBeenCalledWith(expect.any(String), 0));
    const pagePreview = screen.getByRole("heading", { name: "Xem trước trang web" });
    const securityContext = screen.getByText("Ngữ cảnh bảo mật");
    expect(pagePreview.compareDocumentPosition(securityContext) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Chụp ảnh web" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Chụp lại" })).not.toBeInTheDocument();
    const resultDetailLabel = screen.getByText("Xem kết quả chi tiết");
    const resultDetails = resultDetailLabel.closest("details");
    expect(resultDetails).not.toHaveAttribute("open");

    fireEvent.click(resultDetailLabel);

    expect(resultDetails).toHaveAttribute("open");
    expect(screen.getByRole("heading", { name: "Điểm số và thông tin kỹ thuật" })).toBeVisible();

    // The conversation is composer-owned prose. Evidence and actions remain
    // available in the case workspace, rather than being restyled into a
    // second fixed security report beneath the chat message.
    expect(within(assistant).queryByText("Các bước nên làm")).not.toBeInTheDocument();
    expect(within(assistant).queryByText("Vì sao mình đưa ra lời khuyên này?")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /danger\.example/i })).not.toBeInTheDocument();
    expect(screen.queryByText("Lưu lại tin nhắn để báo cáo")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Kỹ thuật" }));
    expect(screen.getAllByText(evidenceRef).length).toBeGreaterThan(0);
    expect(screen.getByText("Lưu lại tin nhắn để báo cáo")).toBeInTheDocument();
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
      reason: "Cần xem lại", comment: null, status: "submitted", decision: null,
      resolution: null, remediation_action: "none", whitelist_entry: null, blacklist_proposal: null,
      remediation_status: "not_requested", remediation_reference: null,
      reviewer_id: null, review_note: null, created_at: "2026-08-13T08:00:00Z", reviewed_at: null,
    });
    vi.mocked(api.createAppeal).mockResolvedValue({
      contract_version: "v4", appeal_id: "appeal-1", analysis_id: "analysis-1",
      reason: "Bằng chứng chưa phù hợp", comment: null, status: "submitted", outcome: null,
      resolution_note: null, reviewer_id: null, created_at: "2026-08-13T08:00:00Z", resolved_at: null,
    });
    render(<AnalysisWorkspace api={api} />);
    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn yêu cầu OTP");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    fireEvent.click(await screen.findByText("Xem kết quả chi tiết"));
    fireEvent.click(await screen.findByText("Báo cáo hoặc yêu cầu xem xét"));
    fireEvent.click(await screen.findByRole("button", { name: "Gửi báo cáo" }));
    await waitFor(() => expect(api.reportAnalysis).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: /Yêu cầu xem xét lại quyết định/i }));
    fireEvent.change(screen.getByLabelText("Lý do khiếu nại"), { target: { value: "Bằng chứng chưa phù hợp" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi khiếu nại" }));
    await waitFor(() => expect(api.createAppeal).toHaveBeenCalled());
  });

  it("offers a recoverable retry without exposing an unexpected error", async () => {
    const create = vi.fn()
      .mockRejectedValueOnce(new Error("Mất kết nối tạm thời"))
      .mockResolvedValueOnce(response());
    render(<AnalysisWorkspace api={apiWith(create)} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Kiểm tra yêu cầu chuyển tiền");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Không thể hoàn tất đánh giá. Vui lòng thử lại.");
    expect(screen.queryByText("Mất kết nối tạm thời")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Thử lại trường hợp này" }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Cần thêm thông tin")).toBeInTheDocument();
    expect(screen.queryByText("Input 2")).not.toBeInTheDocument();
  });

  it("starts the rejected message as a separate case when the active case does not match", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce(response({
        scope_decision: "IN_SCOPE",
        follow_up_question: null,
        risk: "SUSPICIOUS",
        score: 55,
        confidence: 0.7,
        threat_type: "PHISHING",
        policy_version: "security-risk-v1",
        recommended_actions: ["PROCEED_WITH_CAUTION"],
        explanation: "Cần thận trọng.",
      }))
      .mockRejectedValueOnce(new ApiError("Different case", "NEW_CASE_REQUIRED", false, 409))
      .mockResolvedValueOnce(response({
        conversation_id: "20000000-0000-4000-8000-000000000002",
        conversation_version: 1,
      }));
    render(<AnalysisWorkspace api={apiWith(create)} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn thứ nhất");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    await screen.findByRole("heading", { name: "Đáng ngờ" });

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn BIDV không liên quan");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Nội dung này thuộc một trường hợp bảo mật khác.");
    expect(screen.queryByRole("button", { name: "Thử lại trường hợp này" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Kiểm tra như trường hợp mới" }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(3));
    expect(create.mock.calls[2][0]).toEqual(expect.objectContaining({
      message: "Tin nhắn BIDV không liên quan",
      consent: { external_url_lookup: true, official_source_lookup: true },
    }));
    expect(create.mock.calls[2][0]).not.toHaveProperty("conversation_id");
  });

  it("reloads the latest conversation before resubmitting a stale turn", async () => {
    const create = vi.fn()
      .mockResolvedValueOnce(response({
        scope_decision: "IN_SCOPE",
        follow_up_question: null,
        risk: "SUSPICIOUS",
        score: 55,
        confidence: 0.7,
        threat_type: "PHISHING",
        policy_version: "security-risk-v1",
        recommended_actions: ["PROCEED_WITH_CAUTION"],
        explanation: "Cần thận trọng.",
      }))
      .mockRejectedValueOnce(new ApiError("Stale", "CONVERSATION_VERSION_STALE", true, 409))
      .mockResolvedValueOnce(response({ conversation_version: 3 }));
    const api = apiWith(create);
    vi.mocked(api.getConversation).mockResolvedValue({
      contract_version: "v4",
      conversation_id: "10000000-0000-4000-8000-000000000001",
      context_version: 2,
      active_analysis_id: "analysis-current",
      status: "active",
      summary: { security_context: null, assistant_context: null, unresolved_slots: [], evidence_refs: [] },
      created_at: "2026-08-13T08:00:00Z",
      updated_at: "2026-08-13T08:00:01Z",
      expires_at: "2026-09-13T08:00:01Z",
    });
    render(<AnalysisWorkspace api={api} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn thứ nhất");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    await screen.findByRole("heading", { name: "Đáng ngờ" });

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Tin nhắn cần gửi lại");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    expect(await screen.findByRole("button", { name: "Tải lại hội thoại và gửi lại" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Tải lại hội thoại và gửi lại" }));

    await waitFor(() => expect(api.getConversation).toHaveBeenCalledWith("10000000-0000-4000-8000-000000000001"));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(3));
    expect(create.mock.calls[2][0]).toEqual(expect.objectContaining({ conversation_version: 2 }));
  });

  it("shows the incompatible request field returned by backend validation", async () => {
    const create = vi.fn().mockRejectedValue(new ApiError(
      "Request validation failed.",
      "VALIDATION_ERROR",
      false,
      422,
      { errors: [{ loc: ["body", "execution_mode"], type: "extra_forbidden" }] },
    ));
    render(<AnalysisWorkspace api={apiWith(create)} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Kiểm tra yêu cầu chuyển tiền");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Dữ liệu gửi lên không tương thích ở trường: body.execution_mode.",
    );
  });

  it("renders a terminal failed response without inventing a verdict", async () => {
    const api = apiWith(vi.fn().mockResolvedValue(response({ status: "failed" })));
    render(<AnalysisWorkspace api={api} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Case provider lỗi");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Chưa thể hoàn tất kiểm tra");
    expect(screen.queryByRole("heading", { name: /Nguy hiểm|Rủi ro cao|Đáng ngờ/i })).not.toBeInTheDocument();
  });

  it("ignores a stale create response after the case is reset", async () => {
    let resolveCreate!: (value: SecurityScopeResponseV4) => void;
    const create = vi.fn().mockImplementation(() => new Promise<SecurityScopeResponseV4>((resolve) => {
      resolveCreate = resolve;
    }));
    render(<AnalysisWorkspace api={apiWith(create)} />);

    setComposerMessage(screen.getByLabelText(/Dán tin nhắn đáng ngờ/i), "Case phản hồi chậm");
    fireEvent.click(screen.getByRole("button", { name: /Gửi để đánh giá/i }));
    fireEvent.click(await screen.findByRole("button", { name: "Bắt đầu trường hợp mới" }));
    resolveCreate(response());

    await waitFor(() => expect(screen.getByRole("heading", { name: "Bạn muốn kiểm tra điều gì?" })).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Security investigation workspace" })).not.toBeInTheDocument();
  });
});
