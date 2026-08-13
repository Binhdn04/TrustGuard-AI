import type {
  SecurityAnalysisEventPageV4,
  SecurityAppealRecordV4,
  SecurityReportRecordV4,
  SecurityScopeResponseV4,
  SecurityTriageCreateRequestV4,
  SecurityWebSocketTicketResponseV4,
  BrandRecordV4,
  WhitelistRecordV4,
} from "@/types/generated/api-v4";

import type { AnalysisEventQuery } from "./analysis-api.types";

export interface SecurityAnalysisApi {
  createAnalysis(request: SecurityTriageCreateRequestV4): Promise<SecurityScopeResponseV4>;
  getAnalysis(analysisId: string): Promise<SecurityScopeResponseV4>;
  listAnalyses(): Promise<SecurityScopeResponseV4[]>;
  getAnalysisEvents(analysisId: string, query?: AnalysisEventQuery): Promise<SecurityAnalysisEventPageV4>;
  createWebSocketTicket(analysisId: string): Promise<SecurityWebSocketTicketResponseV4>;
  reportAnalysis(analysisId: string, request: { reason: string; comment?: string }): Promise<SecurityReportRecordV4>;
  listReports(analysisId: string): Promise<SecurityReportRecordV4[]>;
  createAppeal(analysisId: string, request: { reason: string; comment?: string | null }): Promise<SecurityAppealRecordV4>;
  listAnalysisAppeals(analysisId: string): Promise<SecurityAppealRecordV4[]>;
  listBrands(): Promise<BrandRecordV4[]>;
  listWhitelist(): Promise<WhitelistRecordV4[]>;
}
