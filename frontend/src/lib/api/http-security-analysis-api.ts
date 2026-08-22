import type { ErrorEnvelope } from "@/types/analysis";
import type {
  BrandCreateRequestV4,
  BrandPageV4,
  BrandRecordV4,
  IdentityCandidateDecisionRequestV4,
  IdentityCandidatePageV4,
  IdentityCandidateV4,
  SecurityAdminAuditPageV4,
  SecurityAdminCopilotRequestV4,
  SecurityAdminCopilotResponseV4,
  SecurityAnalysisEventPageV4,
  SecurityAnalysisAcceptedResponseV4,
  SecurityAnalysisPageV4,
  SecurityAppealAdminRecordV4,
  SecurityAppealCreateRequestV4,
  SecurityAppealDecisionRequestV4,
  SecurityAppealPageV4,
  SecurityAppealRecordV4,
  SecurityCampaignAuditRecordV4,
  SecurityCampaignDecisionRequestV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityCapabilitiesResponseV4,
  SecurityChatResponseV4,
  SecurityConversationPageV4,
  SecurityConversationV4,
  SecurityDomainIntelligencePageV4,
  SecurityMemoryAuditRecordV4,
  SecurityMemoryCorrectionRequestV4,
  SecurityMemoryPageV4,
  SecurityMemoryRecordV4,
  SecurityReportAdminRecordV4,
  SecurityReportCreateRequestV4,
  SecurityReportDecisionRequestV4,
  SecurityReportPageV4,
  SecurityReportRecordV4,
  SecurityScopeResponseV4,
  SecurityThreatIntelligencePageV4,
  SecurityTriageCreateRequestV4,
  SecurityWebSocketTicketResponseV4,
  WhitelistCreateRequestV4,
  WhitelistPageV4,
  WhitelistRecordV4,
} from "@/types/generated/api-v4";
import type {
  AdminActionAuditRecordV3,
  AdminActionDecisionRequestV3,
  AdminActionDecisionResponseV3,
  AdminActionPageV3,
  AdminActionRecordV3,
} from "@/types/generated/api-v3";

import { ApiError } from "./api-error";
import type {
  AnalysisEventQuery,
  IdentityCandidatePageQuery,
  SecurityAdminAuditQuery,
  SecurityAnalysisApi,
  SecurityAnalysisPageQuery,
  SecurityAppealPageQuery,
  SecurityCampaignPageQuery,
  SecurityChatContext,
  SecurityDomainIntelligenceQuery,
  SecurityMemoryPageQuery,
  SecurityPaginationQuery,
  SecurityReportPageQuery,
  SecurityThreatIntelligenceQuery,
  SecurityTrustPageQuery,
} from "./security-analysis-api.types";

const DEFAULT_API_URL = "http://localhost:8000";
type AccessTokenProvider = () => string | null | undefined;

async function readJson<T>(response: Response): Promise<T> {
  const payload = (await response.json()) as T | ErrorEnvelope;
  if (!response.ok) {
    const error = (payload as ErrorEnvelope).error;
    throw new ApiError(
      error?.message ?? "Không thể kết nối tới dịch vụ bảo mật.",
      error?.code ?? "HTTP_ERROR",
      error?.retryable ?? response.status >= 500,
      response.status,
    );
  }
  return payload as T;
}

function withQuery(resource: string, query?: object): string {
  if (!query) return resource;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if ((typeof value === "string" && value.length > 0) || typeof value === "number") {
      search.set(key, String(value));
    }
  }
  return search.size ? `${resource}?${search.toString()}` : resource;
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

  async getCapabilities(): Promise<SecurityCapabilitiesResponseV4> {
    return this.get<SecurityCapabilitiesResponseV4>("capabilities");
  }

  async chat(message: string, context?: SecurityChatContext): Promise<SecurityChatResponseV4> {
    return this.post<SecurityChatResponseV4>("chat", {
      message,
      ...(context
        ? {
            conversation_id: context.conversationId,
            conversation_version: context.conversationVersion,
          }
        : {}),
    });
  }

  async listAdminActions(query: SecurityPaginationQuery & { status?: "pending_review" | "approved" | "rejected" | "executed" | "failed" } = {}): Promise<AdminActionPageV3> {
    return this.get<AdminActionPageV3>(withQuery("admin/actions", query));
  }

  async getAdminAction(actionId: string): Promise<AdminActionRecordV3> {
    return this.get<AdminActionRecordV3>(`admin/actions/${encodeURIComponent(actionId)}`);
  }

  async decideAdminAction(actionId: string, request: AdminActionDecisionRequestV3): Promise<AdminActionDecisionResponseV3> {
    return this.post<AdminActionDecisionResponseV3>(`admin/actions/${encodeURIComponent(actionId)}/decision`, request);
  }

  async listAdminActionAudit(actionId: string): Promise<AdminActionAuditRecordV3[]> {
    return this.get<AdminActionAuditRecordV3[]>(`admin/actions/${encodeURIComponent(actionId)}/audit`);
  }

  async createAnalysis(
    request: SecurityTriageCreateRequestV4,
    options: { idempotencyKey?: string } = {},
  ): Promise<SecurityScopeResponseV4 | SecurityAnalysisAcceptedResponseV4> {
    return this.post<SecurityScopeResponseV4 | SecurityAnalysisAcceptedResponseV4>(
      "analyses",
      request,
      options.idempotencyKey ? { "Idempotency-Key": options.idempotencyKey } : {},
    );
  }

  async getAnalysis(analysisId: string): Promise<SecurityScopeResponseV4> {
    return this.get<SecurityScopeResponseV4>(`analyses/${encodeURIComponent(analysisId)}`);
  }

  async capturePage(analysisId: string, urlIndex: number): Promise<Blob> {
    const response = await fetch(
      `${this.baseUrl}/api/v4/analyses/${encodeURIComponent(analysisId)}/page-capture`,
      {
        method: "POST",
        credentials: "include",
        headers: this.headers(true),
        body: JSON.stringify({ url_index: urlIndex, external_url_lookup: true }),
      },
    );
    if (!response.ok) await readJson<never>(response);
    return response.blob();
  }

  async getAdminAnalysis(analysisId: string): Promise<SecurityScopeResponseV4> {
    return this.get<SecurityScopeResponseV4>(`admin/analyses/${encodeURIComponent(analysisId)}`);
  }

  async draftAdminCopilot(
    analysisId: string,
    request: SecurityAdminCopilotRequestV4,
  ): Promise<SecurityAdminCopilotResponseV4> {
    return this.post<SecurityAdminCopilotResponseV4>(
      `admin/analyses/${encodeURIComponent(analysisId)}/copilot`,
      request,
    );
  }

  async listAnalyses(): Promise<SecurityScopeResponseV4[]> {
    return this.get<SecurityScopeResponseV4[]>("analyses");
  }

  async pageAnalyses(query: SecurityAnalysisPageQuery = {}): Promise<SecurityAnalysisPageV4> {
    return this.get<SecurityAnalysisPageV4>(withQuery("analyses/page", query));
  }

  async getConversation(conversationId: string): Promise<SecurityConversationV4> {
    return this.get<SecurityConversationV4>(`conversations/${encodeURIComponent(conversationId)}`);
  }

  async listConversations(query: SecurityPaginationQuery = {}): Promise<SecurityConversationPageV4> {
    return this.get<SecurityConversationPageV4>(withQuery("conversations", query));
  }

  async getAnalysisEvents(
    analysisId: string,
    query: AnalysisEventQuery = {},
  ): Promise<SecurityAnalysisEventPageV4> {
    return this.get<SecurityAnalysisEventPageV4>(
      withQuery(`analyses/${encodeURIComponent(analysisId)}/events`, query),
    );
  }

  async createWebSocketTicket(analysisId: string): Promise<SecurityWebSocketTicketResponseV4> {
    return this.post<SecurityWebSocketTicketResponseV4>("ws-tickets", { analysis_id: analysisId });
  }

  async reportAnalysis(
    analysisId: string,
    request: SecurityReportCreateRequestV4,
  ): Promise<SecurityReportRecordV4> {
    return this.post<SecurityReportRecordV4>(`analyses/${encodeURIComponent(analysisId)}/reports`, request);
  }

  async listReports(analysisId: string): Promise<SecurityReportRecordV4[]> {
    return this.get<SecurityReportRecordV4[]>(`analyses/${encodeURIComponent(analysisId)}/reports`);
  }

  async createAppeal(
    analysisId: string,
    request: SecurityAppealCreateRequestV4,
  ): Promise<SecurityAppealRecordV4> {
    return this.post<SecurityAppealRecordV4>(`analyses/${encodeURIComponent(analysisId)}/appeals`, request);
  }

  async listAnalysisAppeals(analysisId: string): Promise<SecurityAppealRecordV4[]> {
    return this.get<SecurityAppealRecordV4[]>(`analyses/${encodeURIComponent(analysisId)}/appeals`);
  }

  async listAdminReports(query: SecurityReportPageQuery = {}): Promise<SecurityReportPageV4> {
    return this.get<SecurityReportPageV4>(withQuery("admin/reports", query));
  }

  async decideAdminReport(
    reportId: string,
    request: SecurityReportDecisionRequestV4,
  ): Promise<SecurityReportAdminRecordV4> {
    return this.post<SecurityReportAdminRecordV4>(
      `admin/reports/${encodeURIComponent(reportId)}/decision`,
      request,
    );
  }

  async listAdminAppeals(query: SecurityAppealPageQuery = {}): Promise<SecurityAppealPageV4> {
    return this.get<SecurityAppealPageV4>(withQuery("admin/appeals", query));
  }

  async decideAdminAppeal(
    appealId: string,
    request: SecurityAppealDecisionRequestV4,
  ): Promise<SecurityAppealAdminRecordV4> {
    return this.post<SecurityAppealAdminRecordV4>(
      `admin/appeals/${encodeURIComponent(appealId)}/decision`,
      request,
    );
  }

  async createBrand(request: BrandCreateRequestV4): Promise<BrandRecordV4> {
    return this.post<BrandRecordV4>("admin/brands", request);
  }

  async createBrandVersion(brandId: string, request: BrandCreateRequestV4): Promise<BrandRecordV4> {
    return this.post<BrandRecordV4>(
      `admin/brands/${encodeURIComponent(brandId)}/versions`,
      request,
    );
  }

  async listBrands(): Promise<BrandRecordV4[]> {
    return this.get<BrandRecordV4[]>("admin/brands");
  }

  async pageBrands(query: SecurityTrustPageQuery = {}): Promise<BrandPageV4> {
    return this.get<BrandPageV4>(withQuery("admin/brands/page", query));
  }

  async disableBrand(brandId: string): Promise<BrandRecordV4> {
    return this.post<BrandRecordV4>(`admin/brands/${encodeURIComponent(brandId)}/disable`);
  }

  async pageIdentityCandidates(query: IdentityCandidatePageQuery = {}): Promise<IdentityCandidatePageV4> {
    return this.get<IdentityCandidatePageV4>(withQuery("admin/identity-candidates/page", query));
  }

  async decideIdentityCandidate(
    candidateId: string,
    request: IdentityCandidateDecisionRequestV4,
  ): Promise<IdentityCandidateV4> {
    return this.post<IdentityCandidateV4>(
      `admin/identity-candidates/${encodeURIComponent(candidateId)}/decisions`,
      request,
    );
  }

  async createWhitelist(request: WhitelistCreateRequestV4): Promise<WhitelistRecordV4> {
    return this.post<WhitelistRecordV4>("admin/whitelist", request);
  }

  async listWhitelist(): Promise<WhitelistRecordV4[]> {
    return this.get<WhitelistRecordV4[]>("admin/whitelist");
  }

  async pageWhitelist(query: SecurityTrustPageQuery = {}): Promise<WhitelistPageV4> {
    return this.get<WhitelistPageV4>(withQuery("admin/whitelist/page", query));
  }

  async disableWhitelist(whitelistId: string): Promise<WhitelistRecordV4> {
    return this.post<WhitelistRecordV4>(
      `admin/whitelist/${encodeURIComponent(whitelistId)}/disable`,
    );
  }

  async listSecurityMemory(): Promise<SecurityMemoryRecordV4[]> {
    return this.get<SecurityMemoryRecordV4[]>("admin/security-memory");
  }

  async pageSecurityMemory(query: SecurityMemoryPageQuery = {}): Promise<SecurityMemoryPageV4> {
    return this.get<SecurityMemoryPageV4>(withQuery("admin/security-memory/page", query));
  }

  async correctSecurityMemory(
    memoryId: string,
    request: SecurityMemoryCorrectionRequestV4,
  ): Promise<SecurityMemoryRecordV4> {
    return this.post<SecurityMemoryRecordV4>(
      `admin/security-memory/${encodeURIComponent(memoryId)}/corrections`,
      request,
    );
  }

  async listSecurityMemoryAudit(memoryId: string): Promise<SecurityMemoryAuditRecordV4[]> {
    return this.get<SecurityMemoryAuditRecordV4[]>(
      `admin/security-memory/${encodeURIComponent(memoryId)}/audit`,
    );
  }

  async listSecurityCampaigns(): Promise<SecurityCampaignRecordV4[]> {
    return this.get<SecurityCampaignRecordV4[]>("admin/security-campaigns");
  }

  async pageSecurityCampaigns(
    query: SecurityCampaignPageQuery = {},
  ): Promise<SecurityCampaignPageV4> {
    return this.get<SecurityCampaignPageV4>(withQuery("admin/security-campaigns/page", query));
  }

  async getSecurityCampaign(campaignId: string): Promise<SecurityCampaignRecordV4> {
    return this.get<SecurityCampaignRecordV4>(
      `admin/security-campaigns/${encodeURIComponent(campaignId)}`,
    );
  }

  async reviewSecurityCampaign(
    campaignId: string,
    request: SecurityCampaignDecisionRequestV4,
  ): Promise<SecurityCampaignRecordV4> {
    return this.post<SecurityCampaignRecordV4>(
      `admin/security-campaigns/${encodeURIComponent(campaignId)}/decision`,
      request,
    );
  }

  async listSecurityCampaignAudit(campaignId: string): Promise<SecurityCampaignAuditRecordV4[]> {
    return this.get<SecurityCampaignAuditRecordV4[]>(
      `admin/security-campaigns/${encodeURIComponent(campaignId)}/audit`,
    );
  }

  async listDomainIntelligence(
    query: SecurityDomainIntelligenceQuery = {},
  ): Promise<SecurityDomainIntelligencePageV4> {
    return this.get<SecurityDomainIntelligencePageV4>(
      withQuery("admin/intelligence/domains", query),
    );
  }

  async listThreatIntelligence(
    query: SecurityThreatIntelligenceQuery = {},
  ): Promise<SecurityThreatIntelligencePageV4> {
    return this.get<SecurityThreatIntelligencePageV4>(
      withQuery("admin/intelligence/threats", query),
    );
  }

  async listAdminAudit(query: SecurityAdminAuditQuery = {}): Promise<SecurityAdminAuditPageV4> {
    return this.get<SecurityAdminAuditPageV4>(withQuery("admin/audit", query));
  }

  private async get<T>(resource: string): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v4/${resource}`, {
      credentials: "include",
      headers: this.headers(),
    });
    return readJson<T>(response);
  }

  private async post<T>(resource: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}/api/v4/${resource}`, {
      method: "POST",
      credentials: "include",
      headers: { ...this.headers(body !== undefined), ...extraHeaders },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return readJson<T>(response);
  }
}
