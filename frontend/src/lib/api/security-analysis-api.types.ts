import type {
  BrandCreateRequestV4,
  BrandPageV4,
  BrandRecordV4,
  PotentialThreatV4,
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
  SecurityAppealStatusV4,
  SecurityAuditResourceV4,
  SecurityCampaignAuditRecordV4,
  SecurityCampaignDecisionRequestV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityCampaignReviewerStatusV4,
  SecurityCapabilitiesResponseV4,
  SecurityConversationPageV4,
  SecurityConversationV4,
  SecurityDomainIntelligencePageV4,
  SecurityMemoryAdminVerdictV4,
  SecurityMemoryAuditRecordV4,
  SecurityMemoryCorrectionRequestV4,
  SecurityMemoryPageV4,
  SecurityMemoryRecordV4,
  SecurityReportAdminRecordV4,
  SecurityReportCreateRequestV4,
  SecurityReportDecisionRequestV4,
  SecurityReportPageV4,
  SecurityReportRecordV4,
  SecurityReportStatusV4,
  SecurityRiskV4,
  SecurityScopeDecisionV4,
  SecurityScopeResponseV4,
  SecurityThreatIntelligencePageV4,
  SecurityTriageCreateRequestV4,
  SecurityWebSocketTicketResponseV4,
  TrustLifecycleV4,
  WhitelistCreateRequestV4,
  WhitelistPageV4,
  WhitelistRecordV4,
} from "@/types/generated/api-v4";

import type { AnalysisEventQuery } from "./analysis-api.types";

export interface SecurityPaginationQuery {
  limit?: number;
  offset?: number;
}

export interface SecurityAnalysisPageQuery extends SecurityPaginationQuery {
  scope_decision?: SecurityScopeDecisionV4;
  risk?: SecurityRiskV4;
  threat_type?: PotentialThreatV4;
  q?: string;
}

export interface SecurityTrustPageQuery extends SecurityPaginationQuery {
  lifecycle?: TrustLifecycleV4;
  q?: string;
}

export interface SecurityMemoryPageQuery extends SecurityPaginationQuery {
  q?: string;
  risk?: SecurityRiskV4;
  verdict?: SecurityMemoryAdminVerdictV4;
}

export interface SecurityCampaignPageQuery extends SecurityPaginationQuery {
  status?: SecurityCampaignReviewerStatusV4;
  q?: string;
}

export interface SecurityDomainIntelligenceQuery extends SecurityPaginationQuery {
  q?: string;
  risk?: SecurityRiskV4;
  threat_type?: PotentialThreatV4;
}

export interface SecurityThreatIntelligenceQuery extends SecurityPaginationQuery {
  risk?: SecurityRiskV4;
}

export interface SecurityAdminAuditQuery extends SecurityPaginationQuery {
  resource_type?: SecurityAuditResourceV4;
  action?: string;
}

export interface SecurityReportPageQuery extends SecurityPaginationQuery {
  status?: SecurityReportStatusV4;
  q?: string;
}

export interface SecurityAppealPageQuery extends SecurityPaginationQuery {
  status?: SecurityAppealStatusV4;
  q?: string;
}

export interface SecurityAnalysisApi {
  getCapabilities(): Promise<SecurityCapabilitiesResponseV4>;
  createAnalysis(
    request: SecurityTriageCreateRequestV4,
    options?: { idempotencyKey?: string },
  ): Promise<SecurityScopeResponseV4 | SecurityAnalysisAcceptedResponseV4>;
  getAnalysis(analysisId: string): Promise<SecurityScopeResponseV4>;
  getAdminAnalysis(analysisId: string): Promise<SecurityScopeResponseV4>;
  draftAdminCopilot?(analysisId: string, request: SecurityAdminCopilotRequestV4): Promise<SecurityAdminCopilotResponseV4>;
  listAnalyses(): Promise<SecurityScopeResponseV4[]>;
  pageAnalyses(query?: SecurityAnalysisPageQuery): Promise<SecurityAnalysisPageV4>;
  getConversation(conversationId: string): Promise<SecurityConversationV4>;
  listConversations(query?: SecurityPaginationQuery): Promise<SecurityConversationPageV4>;
  getAnalysisEvents(analysisId: string, query?: AnalysisEventQuery): Promise<SecurityAnalysisEventPageV4>;
  createWebSocketTicket(analysisId: string): Promise<SecurityWebSocketTicketResponseV4>;
  reportAnalysis(analysisId: string, request: SecurityReportCreateRequestV4): Promise<SecurityReportRecordV4>;
  listReports(analysisId: string): Promise<SecurityReportRecordV4[]>;
  createAppeal(analysisId: string, request: SecurityAppealCreateRequestV4): Promise<SecurityAppealRecordV4>;
  listAnalysisAppeals(analysisId: string): Promise<SecurityAppealRecordV4[]>;
  listAdminReports(query?: SecurityReportPageQuery): Promise<SecurityReportPageV4>;
  decideAdminReport(reportId: string, request: SecurityReportDecisionRequestV4): Promise<SecurityReportAdminRecordV4>;
  listAdminAppeals(query?: SecurityAppealPageQuery): Promise<SecurityAppealPageV4>;
  decideAdminAppeal(appealId: string, request: SecurityAppealDecisionRequestV4): Promise<SecurityAppealAdminRecordV4>;
  createBrand(request: BrandCreateRequestV4): Promise<BrandRecordV4>;
  listBrands(): Promise<BrandRecordV4[]>;
  pageBrands(query?: SecurityTrustPageQuery): Promise<BrandPageV4>;
  disableBrand(brandId: string): Promise<BrandRecordV4>;
  createWhitelist(request: WhitelistCreateRequestV4): Promise<WhitelistRecordV4>;
  listWhitelist(): Promise<WhitelistRecordV4[]>;
  pageWhitelist(query?: SecurityTrustPageQuery): Promise<WhitelistPageV4>;
  disableWhitelist(whitelistId: string): Promise<WhitelistRecordV4>;
  listSecurityMemory(): Promise<SecurityMemoryRecordV4[]>;
  pageSecurityMemory(query?: SecurityMemoryPageQuery): Promise<SecurityMemoryPageV4>;
  correctSecurityMemory(memoryId: string, request: SecurityMemoryCorrectionRequestV4): Promise<SecurityMemoryRecordV4>;
  listSecurityMemoryAudit(memoryId: string): Promise<SecurityMemoryAuditRecordV4[]>;
  listSecurityCampaigns(): Promise<SecurityCampaignRecordV4[]>;
  pageSecurityCampaigns(query?: SecurityCampaignPageQuery): Promise<SecurityCampaignPageV4>;
  getSecurityCampaign(campaignId: string): Promise<SecurityCampaignRecordV4>;
  reviewSecurityCampaign(campaignId: string, request: SecurityCampaignDecisionRequestV4): Promise<SecurityCampaignRecordV4>;
  listSecurityCampaignAudit(campaignId: string): Promise<SecurityCampaignAuditRecordV4[]>;
  listDomainIntelligence(query?: SecurityDomainIntelligenceQuery): Promise<SecurityDomainIntelligencePageV4>;
  listThreatIntelligence(query?: SecurityThreatIntelligenceQuery): Promise<SecurityThreatIntelligencePageV4>;
  listAdminAudit(query?: SecurityAdminAuditQuery): Promise<SecurityAdminAuditPageV4>;
}
