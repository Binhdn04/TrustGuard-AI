import type {
  AdminDecisionAudit,
  AdminDecisionRequest,
  AdminDecisionResponse,
  AnalysisAcceptedResponse,
  AnalysisApi,
  AnalysisCreateRequest,
  AnalysisEvent,
  AnalysisReportRequest,
  AnalysisReportRecord,
  AnalysisReportResponse,
  AnalysisResponse,
  BlacklistEntry,
  CaseStatus,
  Evidence,
  InputType,
} from "@/types/analysis";

interface MockRecord {
  request: AnalysisCreateRequest;
  createdAt: string;
  polls: number;
}

const records = new Map<string, MockRecord>();
const reviewedCases = new Map<string, CaseStatus>();
const reports = new Map<string, AnalysisReportRecord[]>();
const decisions: AdminDecisionAudit[] = [];
const blacklist: BlacklistEntry[] = [];
const URL_PATTERN = /https?:\/\/[^\s]+/giu;

function inputTypeFor(message: string): InputType {
  const urls = message.match(URL_PATTERN) ?? [];
  if (urls.length === 0) return "text";
  return message.trim() === urls[0] ? "url" : "text_with_url";
}

function runningResponse(
  analysisId: string,
  createdAt: string,
): AnalysisResponse {
  return {
    contract_version: "v1",
    analysis_id: analysisId,
    status: "running",
    input_type: null,
    normalized_urls: null,
    claims: null,
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
): AnalysisResponse {
  const { message } = record.request;
  const normalizedUrls = message.match(URL_PATTERN) ?? [];
  const normalizedMessage = message.toLocaleLowerCase("vi");
  const observedAt = new Date().toISOString();
  const base = {
    contract_version: "v1" as const,
    analysis_id: analysisId,
    status: "completed" as const,
    input_type: inputTypeFor(message),
    normalized_urls: normalizedUrls,
    claims: [] as string[],
    scoring_version: "risk-v1",
    created_at: record.createdAt,
    completed_at: observedAt,
  };

  let response: AnalysisResponse;

  if (normalizedMessage.includes("official.example/security")) {
    response = {
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
  } else if (
    normalizedMessage.includes("tapdoanx-qua") ||
    normalizedMessage.includes("đăng nhập") ||
    normalizedMessage.includes("phishing")
  ) {
    response = {
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
  } else if (normalizedUrls.length === 0) {
    response = {
      ...base,
      risk_score: 18,
      risk_level: "low",
      verdict: "inconclusive",
      recommended_action: "allow",
      confidence: 0.42,
      summary: "Chưa tìm thấy URL hoặc tuyên bố đủ rõ để kiểm chứng.",
      reasons: ["Nội dung không chứa chỉ dấu có thể đối chiếu tự động."],
      evidence: [],
      limitations: ["Không đủ bằng chứng để kết luận nội dung là an toàn."],
      case_status: "not_required",
    };
  } else {
    response = {
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
  const reviewedStatus = reviewedCases.get(analysisId);
  return reviewedStatus ? { ...response, case_status: reviewedStatus } : response;
}

export class MockAnalysisApi implements AnalysisApi {
  async createAnalysis(
    request: AnalysisCreateRequest,
  ): Promise<AnalysisAcceptedResponse> {
    const analysisId = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    records.set(analysisId, { request, createdAt, polls: 0 });
    reports.set(analysisId, []);
    return {
      contract_version: "v1",
      analysis_id: analysisId,
      status: "queued",
      created_at: createdAt,
    };
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");

    record.polls += 1;
    if (record.polls < 2) return runningResponse(analysisId, record.createdAt);
    return completedResponse(analysisId, record);
  }

  async listAnalyses(): Promise<AnalysisResponse[]> {
    return [...records.entries()]
      .map(([analysisId, record]) => completedResponse(analysisId, record))
      .sort((left, right) => right.created_at.localeCompare(left.created_at));
  }

  async getAnalysisEvents(analysisId: string): Promise<AnalysisEvent[]> {
    const record = records.get(analysisId);
    if (!record) throw new Error("Không tìm thấy phiên phân tích.");
    const completed = completedResponse(analysisId, record);
    return [
      {
        analysis_id: analysisId,
        status: "queued",
        step: "queued",
        occurred_at: record.createdAt,
      },
      {
        analysis_id: analysisId,
        status: "completed",
        step: "completed",
        occurred_at: completed.completed_at ?? record.createdAt,
      },
    ];
  }

  async reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponse> {
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    const receipt: AnalysisReportRecord = {
      report_id: crypto.randomUUID(),
      analysis_id: analysisId,
      reporter_id: "demo-user",
      reason: request.reason,
      comment: request.comment ?? null,
      created_at: new Date().toISOString(),
    };
    reports.get(analysisId)?.push(receipt);
    return receipt;
  }

  async listAdminCases(): Promise<AnalysisResponse[]> {
    return (await this.listAnalyses()).filter(
      (analysis) => analysis.case_status === "pending_review",
    );
  }

  async listAdminReports(): Promise<AnalysisReportRecord[]> {
    return [...reports.values()].flat().sort((left, right) =>
      right.created_at.localeCompare(left.created_at),
    );
  }

  async listAdminDecisions(): Promise<AdminDecisionAudit[]> {
    return [...decisions];
  }

  async listAdminBlacklist(): Promise<BlacklistEntry[]> {
    return [...blacklist];
  }

  async decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse> {
    if (!records.has(analysisId)) throw new Error("Không tìm thấy phiên phân tích.");
    reviewedCases.set(analysisId, request.decision);
    const decisionId = crypto.randomUUID();
    const reviewedAt = new Date().toISOString();
    decisions.unshift({
      decision_id: decisionId,
      analysis_id: analysisId,
      reviewer_id: "demo-admin",
      decision: request.decision,
      action: request.action,
      note: request.note,
      decided_at: reviewedAt,
    });
    if (request.action === "add_to_blacklist") {
      const response = completedResponse(analysisId, records.get(analysisId)!);
      for (const url of response.normalized_urls ?? []) {
        const domain = new URL(url).hostname;
        if (!blacklist.some((entry) => entry.domain === domain)) {
          blacklist.unshift({ domain, decision_id: decisionId, added_at: reviewedAt });
        }
      }
    }
    return {
      decision_id: decisionId,
      analysis_id: analysisId,
      case_status: request.decision,
      reviewed_at: reviewedAt,
    };
  }
}

export function resetMockAnalyses(): void {
  records.clear();
  reviewedCases.clear();
  reports.clear();
  decisions.length = 0;
  blacklist.length = 0;
}
