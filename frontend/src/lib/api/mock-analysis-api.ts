import type {
  AnalysisCreateRequest,
  AnalysisResponse,
  AnalysisReportResponse,
  AdminDecisionAudit,
  BlacklistEntry,
  Evidence,
  InputType,
} from "@/types/analysis";
import type {
  AnalysisAcceptedResponseV3,
  AnalysisEventPageV3,
  AnalysisEventV3,
  AnalysisReportResponseV3,
  AnalysisResponseV3,
} from "@/types/generated/api-v3";

import type { AnalysisApi, AnalysisEventQuery } from "./analysis-api.types";

interface MockRecord {
  request: AnalysisCreateRequest;
  createdAt: string;
  eventPolls: number;
}

const records = new Map<string, MockRecord>();
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
  async createAnalysis(
    request: AnalysisCreateRequest,
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

  async reportAnalysis(analysisId: string): Promise<AnalysisReportResponseV3> {
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    return {
      contract_version: "v3",
      report_id: crypto.randomUUID(),
      analysis_id: analysisId,
      created_at: new Date().toISOString(),
    };
  }
}

export function resetMockAnalyses(): void {
  records.clear();
}
