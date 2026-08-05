import type {
  AnalysisAcceptedResponse,
  AnalysisApi,
  AnalysisCreateRequest,
  AnalysisResponse,
  ErrorEnvelope,
} from "@/types/analysis";

const DEFAULT_API_URL = "http://localhost:8000";

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
    const response = await fetch(`${this.baseUrl}/api/v1/analyses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    return readJson<AnalysisAcceptedResponse>(response);
  }

  async getAnalysis(analysisId: string): Promise<AnalysisResponse> {
    const response = await fetch(
      `${this.baseUrl}/api/v1/analyses/${encodeURIComponent(analysisId)}`,
      { headers: { Accept: "application/json" } },
    );
    return readJson<AnalysisResponse>(response);
  }
}
