import type {
  AnalysisAcceptedResponse,
  AnalysisApi,
  AnalysisCreateRequest,
  AdminDecisionAudit,
  AnalysisResponse,
  AnalysisReportRequest,
  AnalysisReportResponse,
  BlacklistEntry,
  ErrorEnvelope,
} from "@/types/analysis";

const DEFAULT_API_URL = "http://localhost:8000";

function authHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const stored = window.localStorage.getItem("ai_protect_user");
  const role = stored ? (JSON.parse(stored) as { role?: string }).role : "user";
  return {
    Authorization:
      role === "security_admin"
        ? "Bearer dev-admin-token"
        : "Bearer dev-user-token",
  };
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
    request: AnalysisCreateRequest,
  ): Promise<AnalysisAcceptedResponse> {
    const response = await fetch(`${this.baseUrl}/api/v2/analyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(request),
    });
    return readJson<AnalysisAcceptedResponse>(response);
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v2/analyses/${encodeURIComponent(analysisId)}`,
      { headers: { Accept: "application/json", ...authHeaders() } },
    );
    return readJson<AnalysisResponse>(response);
  }

  async listAnalyses(): Promise<AnalysisResponse[]> {
    const response = await fetch(`${this.baseUrl}/api/v2/analyses`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<AnalysisResponse[]>(response);
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

  async reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v2/analyses/${encodeURIComponent(analysisId)}/reports`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(request),
      },
    );
    return readJson<AnalysisReportResponse>(response);
  }

  private async getAdminResource<T>(resource: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v2/admin/${resource}`, {
      headers: { Accept: "application/json", ...authHeaders() },
    });
    return readJson<T>(response);
  }
}
