import type {
  AdminDecisionAudit,
  AnalysisResponse,
  AnalysisReportRequest,
  AnalysisReportResponse,
  BlacklistEntry,
  ErrorEnvelope,
} from "@/types/analysis";
import type {
  AnalysisAcceptedResponseV3,
  AnalysisCreateRequestV3,
  AnalysisEventPageV3,
  AnalysisReportResponseV3,
  AnalysisResponseV3,
} from "@/types/generated/api-v3";

import type { AnalysisApi, AnalysisEventQuery } from "./analysis-api.types";

const DEFAULT_API_URL = "http://localhost:8000";

type AccessTokenProvider = () => string | null | undefined;

function authHeaders(getAccessToken?: AccessTokenProvider): Record<string, string> {
  const token = getAccessToken?.()?.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
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

  constructor(
    baseUrl = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL,
    private readonly getAccessToken?: AccessTokenProvider,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private requestHeaders(headers: Record<string, string>): Record<string, string> {
    return { ...headers, ...authHeaders(this.getAccessToken) };
  }

  async createAnalysis(
    request: AnalysisCreateRequestV3,
  ): Promise<AnalysisAcceptedResponseV3> {
    const response = await fetch(`${this.baseUrl}/api/v3/analyses`, {
      method: "POST",
      credentials: "include",
      headers: this.requestHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(request),
    });
    return readJson<AnalysisAcceptedResponseV3>(response);
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponseV3> {
    const response = await fetch(
      `${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      {
        credentials: "include",
        headers: this.requestHeaders({ Accept: "application/json" }),
      },
    );
    return readJson<AnalysisResponseV3>(response);
  }

  async listAnalyses(): Promise<AnalysisResponseV3[]> {
    const response = await fetch(`${this.baseUrl}/api/v3/analyses`, {
      credentials: "include",
      headers: this.requestHeaders({ Accept: "application/json" }),
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
      {
        credentials: "include",
        headers: this.requestHeaders({ Accept: "application/json" }),
      },
    );
    return readJson<AnalysisEventPageV3>(response);
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
  ): Promise<AnalysisReportResponseV3> {
    const response = await fetch(
      `${this.baseUrl}/api/v3/analyses/${encodeURIComponent(analysisId)}/reports`,
      {
        method: "POST",
        credentials: "include",
        headers: this.requestHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(request),
      },
    );
    return readJson<AnalysisReportResponseV3>(response);
  }

  private async getAdminResource<T>(resource: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v2/admin/${resource}`, {
      credentials: "include",
      headers: this.requestHeaders({ Accept: "application/json" }),
    });
    return readJson<T>(response);
  }
}
