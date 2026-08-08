import type {
  AdminDecisionAudit,
  AdminDecisionRequest,
  AdminDecisionResponse,
  AnalysisResponse,
  AnalysisReportRequest,
  AnalysisReportResponse,
  BlacklistEntry,
  ErrorEnvelope,
  ReviewQueueItem,
  ReviewQueueDecisionRequest,
} from "@/types/analysis";
import type {
  AnalysisAcceptedResponseV3,
  AnalysisCreateRequestV3,
  AnalysisEventPageV3,
  AnalysisReportResponseV3,
  AnalysisResponseV3,
  WebSocketTicketResponseV3,
} from "@/types/generated/api-v3";

import type { AnalysisApi, AnalysisEventQuery } from "./analysis-api.types";

const DEFAULT_API_URL = "http://localhost:8000";

function authHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const accessToken = window.localStorage.getItem("ai_protect_access_token");
  if (accessToken) return { Authorization: `Bearer ${accessToken}` };

  let role = "user";
  try {
    const stored = window.localStorage.getItem("ai_protect_user");
    role = stored ? (JSON.parse(stored) as { role?: string }).role ?? "user" : "user";
  } catch {
    window.localStorage.removeItem("ai_protect_user");
  }
  const demoToken = role === "security_admin"
    ? process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN
    : process.env.NEXT_PUBLIC_DEMO_USER_TOKEN;
  return demoToken ? { Authorization: `Bearer ${demoToken}` } : {};
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly retryable: boolean,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function readJson<T>(response: Response): Promise<T> {
  const payload = (await response.json()) as T | ErrorEnvelope;

  if (!response.ok) {
    const error = (payload as ErrorEnvelope).error;
    throw new ApiError(
      error?.message ?? "Không thể kết nối tới dịch vụ phân tích.",
      error?.code ?? "HTTP_ERROR",
      error?.retryable ?? response.status >= 500,
      response.status,
    );
  }

  return payload as T;
}

export class HttpAnalysisApi implements AnalysisApi {
  private readonly baseUrl: string;

  constructor(baseUrl = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async createAnalysis(
    request: AnalysisCreateRequestV3,
  ): Promise<AnalysisAcceptedResponseV3> {
    const response = await fetch(`${this.baseUrl}/api/v3/analyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(request),
    });
    return readJson<AnalysisAcceptedResponseV3>(response);
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponseV3> {
    const response = await fetch(
      `${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      { headers: { Accept: "application/json", ...authHeaders() } },
    );
    return readJson<AnalysisResponseV3>(response);
  }

  async listAnalyses(): Promise<AnalysisResponseV3[]> {
    const response = await fetch(`${this.baseUrl}/api/v3/analyses`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<AnalysisResponseV3[]>(response);
  }

  async getAnalysisEvents(
    analysisId: string,
    query: AnalysisEventQuery = {},
  ): Promise<AnalysisEventPageV3> {
    const search = new URLSearchParams();
    if (query.cursor) search.set("cursor", query.cursor);
    if (query.limit !== undefined) search.set("limit", String(query.limit));
    const suffix = search.size > 0 ? `?${search.toString()}` : "";
    const response = await fetch(
      `${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}/events${suffix}`,
      { headers: { Accept: "application/json", ...authHeaders() } },
    );
    return readJson<AnalysisEventPageV3>(response);
  }

  async createWebSocketTicket(analysisId: string): Promise<WebSocketTicketResponseV3> {
    const response = await fetch(`${this.baseUrl}/api/v3/ws-tickets`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ analysis_id: analysisId }),
    });
    return readJson<WebSocketTicketResponseV3>(response);
  }

  async listAdminCases(): Promise<AnalysisResponse[]> {
    return this.getAdminResource<AnalysisResponse[]>("cases");
  }

  async listAdminReports(): Promise<AnalysisReportResponse[]> {
    return this.getAdminResource<AnalysisReportResponse[]>("reports");
  }

  async listAdminDecisions(): Promise<AdminDecisionAudit[]> {
    return this.getAdminResource<AdminDecisionAudit[]>("decisions");
  }

  async listAdminBlacklist(): Promise<BlacklistEntry[]> {
    return this.getAdminResource<BlacklistEntry[]>("blacklist");
  }

  async decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v2/admin/cases/${encodeURIComponent(analysisId)}/decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(request),
      },
    );
    return readJson<AdminDecisionResponse>(response);
  }

  async reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponseV3> {
    const response = await fetch(
      `${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}/reports`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(request),
      },
    );
    return readJson<AnalysisReportResponseV3>(response);
  }

  async listReports(analysisId: string): Promise<AnalysisReportResponse[]> {
    const response = await fetch(`${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}/reports`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<AnalysisReportResponse[]>(response);
  }

  async listReviewQueueItems(): Promise<ReviewQueueItem[]> {
    const response = await fetch(`${this.baseUrl}/api/v3/admin/review-queue`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<ReviewQueueItem[]>(response);
  }

  async startReviewQueueItem(itemId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v3/admin/review-queue/${encodeURIComponent(itemId)}/start-review`, {
      method: "POST",
      headers: { ...authHeaders() },
    });
    if (!response.ok) {
      const payload = await response.json();
      const error = (payload as ErrorEnvelope).error;
      throw new ApiError(
        error?.message ?? "Không thể bắt đầu xem xét.",
        error?.code ?? "HTTP_ERROR",
        error?.retryable ?? response.status >= 500,
        response.status,
      );
    }
  }

  async decideReviewQueueItem(itemId: string, request: ReviewQueueDecisionRequest): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v3/admin/review-queue/${encodeURIComponent(itemId)}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(request),
    });
    if (!response.ok) {
      const payload = await response.json();
      const error = (payload as ErrorEnvelope).error;
      throw new ApiError(
        error?.message ?? "Không thể lưu quyết định.",
        error?.code ?? "HTTP_ERROR",
        error?.retryable ?? response.status >= 500,
        response.status,
      );
    }
  }

  private async getAdminResource<T>(resource: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v2/admin/${resource}`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<T>(response);
  }
}
