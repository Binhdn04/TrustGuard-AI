import type { ErrorEnvelope } from "@/types/analysis";
import type {
  SecurityAnalysisEventPageV4,
  SecurityAppealRecordV4,
  SecurityReportRecordV4,
  SecurityScopeResponseV4,
  SecurityTriageCreateRequestV4,
  SecurityWebSocketTicketResponseV4,
  BrandRecordV4,
  WhitelistRecordV4,
  SecurityCampaignAuditRecordV4,
  SecurityCampaignRecordV4,
  SecurityCampaignReviewerStatusV4,
  SecurityMemoryAdminVerdictV4,
  SecurityMemoryAuditRecordV4,
  SecurityMemoryRecordV4,
} from "@/types/generated/api-v4";

import { ApiError } from "./http-analysis-api";
import type { AnalysisEventQuery } from "./analysis-api.types";
import type { SecurityAnalysisApi } from "./security-analysis-api.types";

const DEFAULT_API_URL = "http://localhost:8000";
type AccessTokenProvider = () => string | null | undefined;

async function readJson<T>(response: Response): Promise<T> {
  const payload = (await response.json()) as T | ErrorEnvelope;
  if (!response.ok) {
    const error = (payload as ErrorEnvelope).error;
    throw new ApiError(error?.message ?? "Không thể kết nối tới dịch vụ bảo mật.", error?.code ?? "HTTP_ERROR", error?.retryable ?? response.status >= 500, response.status);
  }
  return payload as T;
}

export class HttpSecurityAnalysisApi implements SecurityAnalysisApi {
  private readonly baseUrl: string;

  constructor(
    baseUrl = process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL,
    private readonly getAccessToken?: AccessTokenProvider,
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private headers(contentType = false): Record<string, string> {
    const token = this.getAccessToken?.()?.trim();
    return {
      ...(contentType ? { "Content-Type": "application/json" } : { Accept: "application/json" }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  async createAnalysis(request: SecurityTriageCreateRequestV4): Promise<SecurityScopeResponseV4> {
    const response = await fetch(`${this.baseUrl}/api/v4/analyses`, {
      method: "POST",
      credentials: "include",
      headers: this.headers(true),
      body: JSON.stringify(request),
    });
    return readJson<SecurityScopeResponseV4>(response);
  }

  async getAnalysis(analysisId: string): Promise<SecurityScopeResponseV4> {
    const response = await fetch(`${this.baseUrl}/api/v4/analyses/${encodeURIComponent(analysisId)}`, {
      credentials: "include",
      headers: this.headers(),
    });
    return readJson<SecurityScopeResponseV4>(response);
  }

  async listAnalyses(): Promise<SecurityScopeResponseV4[]> {
    const response = await fetch(`${this.baseUrl}/api/v4/analyses`, {
      credentials: "include",
      headers: this.headers(),
    });
    return readJson<SecurityScopeResponseV4[]>(response);
  }

  async getAnalysisEvents(analysisId: string, query: AnalysisEventQuery = {}): Promise<SecurityAnalysisEventPageV4> {
    const search = new URLSearchParams();
    if (query.cursor) search.set("cursor", query.cursor);
    if (query.limit !== undefined) search.set("limit", String(query.limit));
    const suffix = search.size ? `?${search.toString()}` : "";
    const response = await fetch(`${this.baseUrl}/api/v4/analyses/${encodeURIComponent(analysisId)}/events${suffix}`, {
      credentials: "include",
      headers: this.headers(),
    });
    return readJson<SecurityAnalysisEventPageV4>(response);
  }

  async createWebSocketTicket(analysisId: string): Promise<SecurityWebSocketTicketResponseV4> {
    const response = await fetch(`${this.baseUrl}/api/v4/ws-tickets`, {
      method: "POST",
      credentials: "include",
      headers: this.headers(true),
      body: JSON.stringify({ analysis_id: analysisId }),
    });
    return readJson<SecurityWebSocketTicketResponseV4>(response);
  }

  async reportAnalysis(analysisId: string, request: { reason: string; comment?: string }): Promise<SecurityReportRecordV4> {
    return this.post<SecurityReportRecordV4>(`analyses/${encodeURIComponent(analysisId)}/reports`, request);
  }

  async listReports(analysisId: string): Promise<SecurityReportRecordV4[]> {
    return this.get<SecurityReportRecordV4[]>(`analyses/${encodeURIComponent(analysisId)}/reports`);
  }

  async createAppeal(analysisId: string, request: { reason: string; comment?: string | null }): Promise<SecurityAppealRecordV4> {
    return this.post<SecurityAppealRecordV4>(`analyses/${encodeURIComponent(analysisId)}/appeals`, request);
  }

  async listAnalysisAppeals(analysisId: string): Promise<SecurityAppealRecordV4[]> {
    return this.get<SecurityAppealRecordV4[]>(`analyses/${encodeURIComponent(analysisId)}/appeals`);
  }

  async listBrands(): Promise<BrandRecordV4[]> {
    return this.get<BrandRecordV4[]>("admin/brands");
  }

  async listWhitelist(): Promise<WhitelistRecordV4[]> {
    return this.get<WhitelistRecordV4[]>("admin/whitelist");
  }

  async listSecurityMemory(): Promise<SecurityMemoryRecordV4[]> {
    return this.get<SecurityMemoryRecordV4[]>("admin/security-memory");
  }

  async correctSecurityMemory(memoryId: string, request: { verdict: SecurityMemoryAdminVerdictV4; note: string }): Promise<SecurityMemoryRecordV4> {
    return this.post<SecurityMemoryRecordV4>(`admin/security-memory/${encodeURIComponent(memoryId)}/corrections`, request);
  }

  async listSecurityMemoryAudit(memoryId: string): Promise<SecurityMemoryAuditRecordV4[]> {
    return this.get<SecurityMemoryAuditRecordV4[]>(`admin/security-memory/${encodeURIComponent(memoryId)}/audit`);
  }

  async listSecurityCampaigns(): Promise<SecurityCampaignRecordV4[]> {
    return this.get<SecurityCampaignRecordV4[]>("admin/security-campaigns");
  }

  async getSecurityCampaign(campaignId: string): Promise<SecurityCampaignRecordV4> {
    return this.get<SecurityCampaignRecordV4>(`admin/security-campaigns/${encodeURIComponent(campaignId)}`);
  }

  async reviewSecurityCampaign(campaignId: string, request: { decision: Exclude<SecurityCampaignReviewerStatusV4, "pending_review">; note: string }): Promise<SecurityCampaignRecordV4> {
    return this.post<SecurityCampaignRecordV4>(`admin/security-campaigns/${encodeURIComponent(campaignId)}/decision`, request);
  }

  async listSecurityCampaignAudit(campaignId: string): Promise<SecurityCampaignAuditRecordV4[]> {
    return this.get<SecurityCampaignAuditRecordV4[]>(`admin/security-campaigns/${encodeURIComponent(campaignId)}/audit`);
  }

  private async get<T>(resource: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v4/${resource}`, { credentials: "include", headers: this.headers() });
    return readJson<T>(response);
  }

  private async post<T>(resource: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v4/${resource}`, { method: "POST", credentials: "include", headers: this.headers(true), body: JSON.stringify(body) });
    return readJson<T>(response);
  }
}
