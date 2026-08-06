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
  ErrorEnvelope,
} from "@/types/analysis";

const DEFAULT_API_URL = "http://localhost:8000";
const DEFAULT_USER_TOKEN = "dev-user-token";
const DEFAULT_ADMIN_TOKEN = "dev-admin-token";

function demoToken(): string {
  if (typeof window === "undefined") return DEFAULT_USER_TOKEN;
  try {
    const stored = window.localStorage.getItem("ai_protect_user");
    const role = stored ? (JSON.parse(stored) as { role?: string }).role : "user";
    return role === "security_admin"
      ? (process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN ?? DEFAULT_ADMIN_TOKEN)
      : (process.env.NEXT_PUBLIC_DEMO_USER_TOKEN ?? DEFAULT_USER_TOKEN);
  } catch {
    return DEFAULT_USER_TOKEN;
  }
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

  private headers(json = false): HeadersInit {
    return {
      Accept: "application/json",
      Authorization: `Bearer ${demoToken()}`,
      ...(json ? { "Content-Type": "application/json" } : {}),
    };
  }

  async createAnalysis(
    request: AnalysisCreateRequest,
  ): Promise<AnalysisAcceptedResponse> {
    const response = await fetch(`${this.baseUrl}/api/v1/analyses`, {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify(request),
    });
    return readJson<AnalysisAcceptedResponse>(response);
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/analyses/${encodeURIComponent(analysisId)}`,
      { headers: this.headers() },
    );
    return readJson<AnalysisResponse>(response);
  }

  async listAnalyses(): Promise<AnalysisResponse[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/analyses`, {
      headers: this.headers(),
    });
    return readJson<AnalysisResponse[]>(response);
  }

  async getAnalysisEvents(analysisId: string): Promise<AnalysisEvent[]> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/analyses/${encodeURIComponent(analysisId)}/events`,
      { headers: this.headers() },
    );
    return readJson<AnalysisEvent[]>(response);
  }

  async reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/analyses/${encodeURIComponent(analysisId)}/reports`,
      {
        method: "POST",
        headers: this.headers(true),
        body: JSON.stringify(request),
      },
    );
    return readJson<AnalysisReportResponse>(response);
  }

  async listAdminCases(): Promise<AnalysisResponse[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/admin/cases`, {
      headers: this.headers(),
    });
    return readJson<AnalysisResponse[]>(response);
  }

  async listAdminReports(): Promise<AnalysisReportRecord[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/admin/reports`, {
      headers: this.headers(),
    });
    return readJson<AnalysisReportRecord[]>(response);
  }

  async listAdminDecisions(): Promise<AdminDecisionAudit[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/admin/decisions`, {
      headers: this.headers(),
    });
    return readJson<AdminDecisionAudit[]>(response);
  }

  async listAdminBlacklist(): Promise<BlacklistEntry[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/admin/blacklist`, {
      headers: this.headers(),
    });
    return readJson<BlacklistEntry[]>(response);
  }

  async decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/admin/cases/${encodeURIComponent(analysisId)}/decision`,
      {
        method: "POST",
        headers: this.headers(true),
        body: JSON.stringify(request),
      },
    );
    return readJson<AdminDecisionResponse>(response);
  }
}
