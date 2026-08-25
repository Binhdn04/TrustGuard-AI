import type {
  BrandCreateRequestV4,
  BrandPageV4,
  BrandRecordV4,
  IdentityAssociationAssuranceV4,
  IdentityCandidateDecisionRequestV4,
  IdentityCandidatePageV4,
  IdentityCandidateV4,
  IdentityRelationshipV4,
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
  SecurityBlacklistActionProposalV4,
  SecurityBlacklistAuditRecordV4,
  SecurityBlacklistDecisionRequestV4,
  SecurityBlacklistDecisionResponseV4,
  SecurityBlacklistDisableRequestV4,
  SecurityBlacklistLifecycleV4,
  SecurityBlacklistPageV4,
  SecurityBlacklistProposalRequestV4,
  SecurityBlacklistRecordV4,
  SecurityCampaignAuditRecordV4,
  SecurityCampaignDecisionRequestV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityCampaignReviewerStatusV4,
  SecurityCapabilitiesResponseV4,
  SecurityChatResponseV4,
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
import type {
  AdminActionAuditRecordV3,
  AdminActionDecisionRequestV3,
  AdminActionDecisionResponseV3,
  AdminActionPageV3,
  AdminActionRecordV3,
} from "@/types/generated/api-v3";

export interface AnalysisEventQuery {
  cursor?: string | null;
  limit?: number;
}

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

export interface IdentityCandidatePageQuery extends SecurityPaginationQuery {
  status?: IdentityAssociationAssuranceV4;
  relationship?: IdentityRelationshipV4;
  entity?: string;
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

export interface SecurityBlacklistPageQuery extends SecurityPaginationQuery {
  lifecycle?: SecurityBlacklistLifecycleV4;
  q?: string;
}

export interface SecurityChatContext {
  conversationId: string;
  conversationVersion: number;
}

export interface SecurityAnalysisApi {
  getCapabilities(): Promise<SecurityCapabilitiesResponseV4>;
  chat?(message: string, context?: SecurityChatContext): Promise<SecurityChatResponseV4>;
  createAnalysis(
    request: SecurityTriageCreateRequestV4,
    options?: { idempotencyKey?: string },
  ): Promise<SecurityScopeResponseV4 | SecurityAnalysisAcceptedResponseV4>;
  getAnalysis(analysisId: string): Promise<SecurityScopeResponseV4>;
  capturePage?(analysisId: string, urlIndex: number): Promise<Blob>;
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
  listAdminActions?(query?: SecurityPaginationQuery & { status?: "pending_review" | "approved" | "rejected" | "executed" | "failed" }): Promise<AdminActionPageV3>;
  getAdminAction?(actionId: string): Promise<AdminActionRecordV3>;
  decideAdminAction?(actionId: string, request: AdminActionDecisionRequestV3): Promise<AdminActionDecisionResponseV3>;
  listAdminActionAudit?(actionId: string): Promise<AdminActionAuditRecordV3[]>;
  createBrand(request: BrandCreateRequestV4): Promise<BrandRecordV4>;
  createBrandVersion(brandId: string, request: BrandCreateRequestV4): Promise<BrandRecordV4>;
  listBrands(): Promise<BrandRecordV4[]>;
  pageBrands(query?: SecurityTrustPageQuery): Promise<BrandPageV4>;
  disableBrand(brandId: string): Promise<BrandRecordV4>;
  pageIdentityCandidates?(query?: IdentityCandidatePageQuery): Promise<IdentityCandidatePageV4>;
  decideIdentityCandidate?(candidateId: string, request: IdentityCandidateDecisionRequestV4): Promise<IdentityCandidateV4>;
  createWhitelist(request: WhitelistCreateRequestV4): Promise<WhitelistRecordV4>;
  listWhitelist(): Promise<WhitelistRecordV4[]>;
  pageWhitelist(query?: SecurityTrustPageQuery): Promise<WhitelistPageV4>;
  disableWhitelist(whitelistId: string): Promise<WhitelistRecordV4>;
  pageBlacklist?(query?: SecurityBlacklistPageQuery): Promise<SecurityBlacklistPageV4>;
  getBlacklist?(blacklistId: string): Promise<SecurityBlacklistRecordV4>;
  proposeBlacklist?(request: SecurityBlacklistProposalRequestV4): Promise<SecurityBlacklistActionProposalV4>;
  proposeDisableBlacklist?(blacklistId: string, request: SecurityBlacklistDisableRequestV4): Promise<SecurityBlacklistActionProposalV4>;
  decideBlacklistAction?(actionId: string, request: SecurityBlacklistDecisionRequestV4): Promise<SecurityBlacklistDecisionResponseV4>;
  listBlacklistAudit?(blacklistId: string): Promise<SecurityBlacklistAuditRecordV4[]>;
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
