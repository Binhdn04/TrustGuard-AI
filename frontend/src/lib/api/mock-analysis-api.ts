import type {
  AdminDecisionAudit,
  AdminDecisionRequest,
  AdminDecisionResponse,
  AnalysisResponse,
  AnalysisReportRequest,
  AnalysisReportResponse,
  BlacklistEntry,
  ReviewQueueItem,
  ReviewQueueDecisionRequest,
  Evidence,
  InputType,
} from "@/types/analysis";
import type {
  AnalysisAcceptedResponseV3,
  AnalysisCreateRequestV3,
  AnalysisEventPageV3,
  AnalysisEventV3,
  AnalysisReportResponseV3,
  AnalysisResponseV3,
  AdminActionDecisionRequestV3,
  AdminActionDecisionResponseV3,
  AdminActionAuditRecordV3,
  AdminActionPageV3,
  AppealCreateRequestV3,
  AppealDecisionRequestV3,
  AppealDecisionResponseV3,
  AppealPageV3,
  AppealReceiptV3,
  AppealResponseV3,
  CampaignDetailV3,
  CampaignDecisionRequestV3,
  CampaignPageV3,
  CapabilitiesResponseV3,
  OperationsMetricsResponseV3,
  ScreenshotStatusResponseV3,
  SourcePolicyCreateRequestV3,
  SourcePolicyRecordV3,
  SourceDiscoveryRecordV3,
  SourceDiscoveryDecisionRequestV3,
  WebSocketTicketResponseV3,
} from "@/types/generated/api-v3";

import type { AnalysisApi, AnalysisEventQuery } from "./analysis-api.types";

interface MockRecord {
  request: AnalysisCreateRequestV3;
  createdAt: string;
  eventPolls: number;
}

const records = new Map<string, MockRecord>();
const appeals = new Map<string, AppealResponseV3>();
const sourcePolicies: SourcePolicyRecordV3[] = [];
const URL_PATTERN = /https?:\/\/[^\s]+/giu;

function inputTypeFor(message: string): InputType {
  const urls = message.match(URL_PATTERN) ?? [];
  if (urls.length === 0) return "text";
  return message.trim() === urls[0] ? "url" : "text_with_url";
}

function runningResponse(
  analysisId: string,
  createdAt: string,
): AnalysisResponseV3 {
  return {
    contract_version: "v3",
    analysis_id: analysisId,
    status: "running",
    input_type: null,
    normalized_urls: null,
    claims: null,
    investigation_plan: [],
    risk_score: null,
    risk_level: null,
    verdict: null,
    recommended_action: null,
    confidence: null,
    summary: null,
    reasons: null,
    evidence: null,
    limitations: null,
    case_status: null,
    scoring_version: null,
    created_at: createdAt,
    completed_at: null,
  };
}

function evidence(
  type: Evidence["type"],
  source: string,
  title: string,
  finding: string,
  observedAt: string,
  url: string | null = null,
): Evidence {
  return { type, source, title, finding, observed_at: observedAt, url };
}

function completedResponse(
  analysisId: string,
  record: MockRecord,
): AnalysisResponseV3 {
  const { message } = record.request;
  const normalizedUrls = message.match(URL_PATTERN) ?? [];
  const normalizedMessage = message.toLocaleLowerCase("vi");
  const observedAt = new Date().toISOString();
  const base = {
    contract_version: "v3" as const,
    analysis_id: analysisId,
    status: "completed" as const,
    input_type: inputTypeFor(message),
    normalized_urls: normalizedUrls,
    claims: inputTypeFor(message) === "url" ? [] : [message],
    investigation_plan: [
      {
        step_id: "step-mock-local",
        tool: "local_rules" as const,
        target: "message",
        reason_code: "input_validation",
        depends_on: [] as string[],
        status: "completed" as const,
      },
    ],
    scoring_version: "risk-v2",
    created_at: record.createdAt,
    completed_at: observedAt,
  };

  if (normalizedMessage.includes("nước chanh") || normalizedMessage.includes("ung thư")) {
    return {
      ...base,
      risk_score: 70,
      risk_level: "high",
      verdict: "malicious",
      recommended_action: "show_caution",
      confidence: 0.9,
      summary: "Các nguồn kiểm chứng y khoa bác bỏ phát biểu rằng nước chanh có thể chữa khỏi ung thư.",
      reasons: ["Nguồn fact-check có nhãn đánh giá rõ ràng và liên quan trực tiếp đến phát biểu."],
      evidence: [
        evidence(
          "fact_check",
          "WHO Fact Check",
          "Không có thực phẩm đơn lẻ nào chữa khỏi ung thư",
          "False",
          observedAt,
          "https://www.who.int/health-topics/cancer",
        ),
      ],
      limitations: ["Kết quả demo sử dụng fixture, không thay thế tư vấn y khoa."],
      case_status: "pending_review",
    };
  }

  if (normalizedMessage.includes("xe máy") && normalizedMessage.includes("2027")) {
    return {
      ...base,
      risk_score: 45,
      risk_level: "medium",
      verdict: "inconclusive",
      recommended_action: "show_caution",
      confidence: 0.76,
      summary: "Phát biểu diễn giải quá rộng so với phạm vi và lộ trình được công bố.",
      reasons: ["Nguồn liên quan cho thấy chính sách có phạm vi và điều kiện cụ thể."],
      evidence: [
        evidence(
          "fact_check",
          "Fixture Fact Check Việt Nam",
          "Lộ trình hạn chế phương tiện không đồng nghĩa cấm hoàn toàn trên cả nước.",
          "Mixed",
          observedAt,
          "https://example.com/fact-check/xe-may-2027",
        ),
      ],
      limitations: ["Cần đối chiếu văn bản chính sách mới nhất khi backend corpus được triển khai."],
      case_status: "not_required",
    };
  }

  if (normalizedMessage.includes("official.example/security")) {
    return {
      ...base,
      risk_score: 8,
      risk_level: "low",
      verdict: "safe",
      recommended_action: "allow",
      confidence: 0.91,
      summary:
        "Chưa phát hiện tín hiệu rủi ro đáng kể trong các bằng chứng hiện có.",
      reasons: ["Tên miền khớp với nguồn chính thức trong dữ liệu kiểm tra."],
      evidence: [
        evidence(
          "official_source",
          "official-domain-registry",
          "Tên miền chính thức",
          "Tên miền xuất hiện trong danh sách nguồn chính thức.",
          observedAt,
          "https://official.example/security",
        ),
      ],
      limitations: [],
      case_status: "not_required",
    };
  }

  if (
    normalizedMessage.includes("tapdoanx-qua") ||
    normalizedMessage.includes("đăng nhập") ||
    normalizedMessage.includes("phishing")
  ) {
    return {
      ...base,
      risk_score: 92,
      risk_level: "critical",
      verdict: "malicious",
      recommended_action: "escalate_for_review",
      confidence: 0.94,
      summary:
        "Liên kết có nhiều tín hiệu mạo danh và đang được chuyển cho đội an ninh xem xét.",
      reasons: [
        "Tên miền có dấu hiệu mạo danh thương hiệu.",
        "Đường dẫn yêu cầu đăng nhập trên một domain không chính thức.",
        "Nhiều tín hiệu độc lập cùng chỉ tới nguy cơ đánh cắp thông tin.",
      ],
      evidence: [
        evidence(
          "url_rule",
          "local-url-rules",
          "Phát hiện domain tương tự thương hiệu",
          "Domain chứa tên thương hiệu kèm từ khóa quà tặng bất thường.",
          observedAt,
        ),
        evidence(
          "domain_reputation",
          "mock-url-reputation",
          "Kết quả kiểm tra độ uy tín",
          "Provider mô phỏng đánh dấu brand look-alike và credential path.",
          observedAt,
        ),
      ],
      limitations: [
        "Đây là dữ liệu mô phỏng phục vụ phát triển giao diện; chưa gọi provider thật.",
      ],
      case_status: "pending_review",
    };
  }

  if (normalizedUrls.length === 0) {
    return {
      ...base,
      risk_score: 18,
      risk_level: "low",
      verdict: "inconclusive",
      recommended_action: "allow",
      confidence: 0.42,
      summary: "Chưa tìm thấy nguồn đủ rõ để kiểm chứng phát biểu.",
      reasons: ["Kho dữ liệu mô phỏng chưa có nguồn liên quan trực tiếp."],
      evidence: [],
      limitations: ["Không đủ bằng chứng để kết luận nội dung là an toàn."],
      case_status: "not_required",
    };
  }

  return {
    ...base,
    risk_score: record.request.consent_to_scan_urls ? 48 : 38,
    risk_level: "medium",
    verdict: "inconclusive",
    recommended_action: "show_caution",
    confidence: record.request.consent_to_scan_urls ? 0.61 : 0.38,
    summary: "Liên kết cần được thận trọng vì chưa có đủ bằng chứng xác thực.",
    reasons: ["Domain chưa nằm trong danh sách nguồn chính thức đã biết."],
    evidence: [
      evidence(
        "url_rule",
        "local-url-rules",
        "Kiểm tra cấu trúc URL",
        "URL đã được nhận diện nhưng chưa đủ dữ liệu để xác nhận uy tín.",
        observedAt,
      ),
    ],
    limitations: record.request.consent_to_scan_urls
      ? ["Provider mô phỏng chưa có dữ liệu reputation cho domain này."]
      : ["Bạn chưa cho phép quét URL qua dịch vụ bên ngoài."],
    case_status: "not_required",
  };
}

export class MockAnalysisApi implements AnalysisApi {
  async getCapabilities(): Promise<CapabilitiesResponseV3> {
    return { contract_version: "v3", profile: "offline", capabilities: {} };
  }
  async createAnalysis(
    request: AnalysisCreateRequestV3,
  ): Promise<AnalysisAcceptedResponseV3> {
    const analysisId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    records.set(analysisId, { request, createdAt, eventPolls: 0 });
    return {
      contract_version: "v3",
      analysis_id: analysisId,
      status: "queued",
      created_at: createdAt,
    };
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponseV3> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");

    if (record.eventPolls < 2) return runningResponse(analysisId, record.createdAt);
    return completedResponse(analysisId, record);
  }

  async listAnalyses(): Promise<AnalysisResponseV3[]> {
    return [...records.entries()].map(([analysisId, record]) => completedResponse(analysisId, record));
  }

  async getAnalysisEvents(
    analysisId: string,
    query: AnalysisEventQuery = {},
  ): Promise<AnalysisEventPageV3> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");
    record.eventPolls += 1;

    const occurredAt = new Date().toISOString();
    const events: AnalysisEventV3[] = [
      {
        event_id: `${analysisId}:event:1`,
        analysis_id: analysisId,
        sequence: 1,
        event_type: "analysis_status",
        occurred_at: occurredAt,
        payload: { status: "running" },
      },
      {
        event_id: `${analysisId}:event:2`,
        analysis_id: analysisId,
        sequence: 2,
        event_type: "step_transition",
        occurred_at: occurredAt,
        payload: {
          step_id: "step-mock-local",
          tool: "local_rules",
          target: "message",
          reason_code: "input_validation",
          depends_on: [],
          status: "completed",
        },
      },
      {
        event_id: `${analysisId}:event:3`,
        analysis_id: analysisId,
        sequence: 3,
        event_type: "step_transition",
        occurred_at: occurredAt,
        payload: {
          step_id: "step-mock-claim",
          tool: "claim_retriever",
          target: record.request.message,
          reason_code: "claim_requires_verification",
          depends_on: ["step-mock-local"],
          status: "running",
        },
      },
      {
        event_id: `${analysisId}:event:4`,
        analysis_id: analysisId,
        sequence: 4,
        event_type: "step_transition",
        occurred_at: occurredAt,
        payload: {
          step_id: "step-mock-claim",
          tool: "claim_retriever",
          target: record.request.message,
          reason_code: "claim_requires_verification",
          depends_on: ["step-mock-local"],
          status: "completed",
        },
      },
      {
        event_id: `${analysisId}:event:5`,
        analysis_id: analysisId,
        sequence: 5,
        event_type: "final_result",
        occurred_at: occurredAt,
        payload: { result_ref: `analysis:${analysisId}:result`, status: "completed" },
      },
    ];
    const availableSequence = record.eventPolls === 1 ? 3 : events.length;
    const afterSequence = Number(query.cursor ?? 0);
    const page = events
      .filter((event) => event.sequence > afterSequence && event.sequence <= availableSequence)
      .slice(0, query.limit ?? 100);
    return {
      contract_version: "v3",
      events: page,
      next_cursor: page.length > 0 ? String(page.at(-1)?.sequence) : query.cursor ?? null,
    };
  }

  async createWebSocketTicket(): Promise<WebSocketTicketResponseV3> {
    throw new Error("Mock adapter uses polling and does not expose WebSocket tickets.");
  }

  async listAdminCases(): Promise<AnalysisResponse[]> {
    return (await this.listAnalyses())
      .filter((item) => item.case_status === "pending_review")
      .map((item) => ({
        ...item,
        contract_version: "v2" as const,
      }));
  }

  async listAdminReports(): Promise<AnalysisReportResponse[]> {
    return [];
  }

  async listAdminDecisions(): Promise<AdminDecisionAudit[]> {
    return [];
  }

  async listAdminBlacklist(): Promise<BlacklistEntry[]> {
    return [];
  }

  async decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse> {
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    return {
      decision_id: crypto.randomUUID(),
      analysis_id: analysisId,
      case_status: request.decision,
      reviewed_at: new Date().toISOString(),
    };
  }

  async reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponseV3> {
    void request;
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    return {
      contract_version: "v3",
      report_id: crypto.randomUUID(),
      analysis_id: analysisId,
      created_at: new Date().toISOString(),
    };
  }

  async listReports(_analysisId: string): Promise<AnalysisReportResponse[]> {
    void _analysisId;
    return [];
  }

  async createAppeal(
    analysisId: string,
    request: AppealCreateRequestV3,
  ): Promise<AppealReceiptV3> {
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    const appealId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    appeals.set(appealId, {
      contract_version: "v3",
      appeal_id: appealId,
      analysis_id: analysisId,
      status: "submitted",
      reason: request.reason,
      comment: request.comment ?? null,
      outcome: null,
      resolution_note: null,
      created_at: createdAt,
      resolved_at: null,
    });
    return {
      contract_version: "v3",
      appeal_id: appealId,
      analysis_id: analysisId,
      status: "submitted",
      created_at: createdAt,
    };
  }

  async getAppeal(appealId: string): Promise<AppealResponseV3> {
    const appeal = appeals.get(appealId);
    if (!appeal) throw new Error("Không tìm thấy khiếu nại.");
    return appeal;
  }

  async listAnalysisAppeals(analysisId: string): Promise<AppealResponseV3[]> {
    return [...appeals.values()]
      .filter((appeal) => appeal.analysis_id === analysisId)
      .sort((left, right) => right.created_at.localeCompare(left.created_at));
  }

  async getScreenshotStatus(analysisId: string): Promise<ScreenshotStatusResponseV3> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");
    const consented = record.request.consent_to_capture_screenshot === true;
    return {
      contract_version: "v3",
      analysis_id: analysisId,
      consented,
      status: consented ? "failed" : "not_requested",
      artifact: null,
      failure_code: consented ? "capture_unavailable" : null,
    };
  }

  async listAdminAppeals(): Promise<AppealPageV3> {
    const items = [...appeals.values()].map((appeal) => ({ ...appeal, owner_id: "mock-user" }));
    return { contract_version: "v3", items, total: items.length, limit: 50, offset: 0 };
  }

  async decideAppeal(
    appealId: string,
    request: AppealDecisionRequestV3,
  ): Promise<AppealDecisionResponseV3> {
    const appeal = await this.getAppeal(appealId);
    const decidedAt = new Date().toISOString();
    appeals.set(appealId, {
      ...appeal,
      status: "resolved",
      outcome: request.outcome,
      resolution_note: request.note,
      resolved_at: decidedAt,
    });
    return {
      contract_version: "v3",
      appeal_id: appealId,
      decision_id: crypto.randomUUID(),
      outcome: request.outcome,
      decided_at: decidedAt,
    };
  }

  async listAdminActions(): Promise<AdminActionPageV3> {
    return { contract_version: "v3", items: [], total: 0, limit: 50, offset: 0 };
  }

  async decideAdminAction(
    actionId: string,
    request: AdminActionDecisionRequestV3,
  ): Promise<AdminActionDecisionResponseV3> {
    return {
      contract_version: "v3",
      action_id: actionId,
      decision_id: crypto.randomUUID(),
      action: "none",
      status: request.decision === "approved" ? "failed" : "rejected",
      reviewed_at: new Date().toISOString(),
      executed_at: request.decision === "approved" ? new Date().toISOString() : null,
      execution_error: request.decision === "approved" ? "ACTION_SINK_NOT_CONFIGURED" : null,
    };
  }

  async listAdminActionAudit(_actionId: string): Promise<AdminActionAuditRecordV3[]> {
    void _actionId;
    return [];
  }

  async listCampaigns(): Promise<CampaignPageV3> {
    return { contract_version: "v3", items: [], total: 0, limit: 50, offset: 0 };
  }

  async getCampaign(_campaignId: string): Promise<CampaignDetailV3> {
    void _campaignId;
    throw new Error("Không tìm thấy chiến dịch.");
  }

  async reviewCampaign(
    campaignId: string,
    _request: CampaignDecisionRequestV3,
  ): Promise<CampaignDetailV3> {
    void _request;
    return this.getCampaign(campaignId);
  }

  async listSourcePolicies(): Promise<SourcePolicyRecordV3[]> {
    return [...sourcePolicies];
  }

  async createSourcePolicy(request: SourcePolicyCreateRequestV3): Promise<SourcePolicyRecordV3> {
    const item: SourcePolicyRecordV3 = {
      ...request,
      contract_version: "v3",
      source_id: crypto.randomUUID(),
      active: true,
      reviewer_id: "mock-admin",
      reviewed_at: new Date().toISOString(),
    };
    sourcePolicies.push(item);
    return item;
  }

  async listSourceDiscoveries(): Promise<SourceDiscoveryRecordV3[]> {
    return [];
  }

  async decideSourceDiscovery(
    _domain: string,
    _request: SourceDiscoveryDecisionRequestV3,
  ): Promise<SourceDiscoveryRecordV3> {
    void _domain;
    void _request;
    throw new Error("Không tìm thấy source discovery.");
  }

  async getOperationsMetrics(from: string, to: string): Promise<OperationsMetricsResponseV3> {
    return {
      contract_version: "v3",
      window: { started_at: from, ended_at: to },
      generated_at: new Date().toISOString(),
      latency: [],
      cache: [],
      usage: [],
      risk_distribution: [],
      feedback: {
        reports: 0,
        appeals: appeals.size,
        appeals_upheld: 0,
        appeals_overturned: 0,
        appeals_inconclusive: 0,
        false_positive_rate: null,
      },
    };
  }

  async listReviewQueueItems(): Promise<ReviewQueueItem[]> {
    return [];
  }

  async startReviewQueueItem(_itemId: string): Promise<void> {
    void _itemId;
    return;
  }

  async decideReviewQueueItem(
    _itemId: string,
    _request: ReviewQueueDecisionRequest,
  ): Promise<void> {
    void _itemId;
    void _request;
    return;
  }
}

export function resetMockAnalyses(): void {
  records.clear();
  appeals.clear();
}
