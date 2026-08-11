import type {
  AdminDecisionAudit,
  AdminDecisionRequest,
  AdminDecisionResponse,
  AnalysisReportRequest,
  AnalysisReportResponse,
  AnalysisResponse,
  BlacklistEntry,
  ReviewQueueItem,
  ReviewQueueDecisionRequest,
} from "@/types/analysis";
import type {
  AnalysisAcceptedResponseV3,
  AnalysisCreateRequestV3,
  AnalysisEventPageV3,
  AnalysisReportResponseV3,
  AnalysisResponseV3,
  AdminActionDecisionRequestV3,
  AdminActionDecisionResponseV3,
  AdminActionPageV3,
  AppealCreateRequestV3,
  AppealDecisionRequestV3,
  AppealDecisionResponseV3,
  AppealPageV3,
  AppealReceiptV3,
  AppealResponseV3,
  CampaignDetailV3,
  CampaignPageV3,
  OperationsMetricsResponseV3,
  ScreenshotStatusResponseV3,
  WebSocketTicketResponseV3,
} from "@/types/generated/api-v3";

export interface AnalysisEventQuery {
  cursor?: string | null;
  limit?: number;
}

export interface PageQuery<TStatus extends string> {
  status?: TStatus;
  limit?: number;
  offset?: number;
}

export interface AnalysisApi {
  createAnalysis(request: AnalysisCreateRequestV3): Promise<AnalysisAcceptedResponseV3>;
  getAnalysis(analysisId: string): Promise<AnalysisResponseV3>;
  listAnalyses(): Promise<AnalysisResponseV3[]>;
  getAnalysisEvents(
    analysisId: string,
    query?: AnalysisEventQuery,
  ): Promise<AnalysisEventPageV3>;
  createWebSocketTicket(analysisId: string): Promise<WebSocketTicketResponseV3>;
  reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponseV3>;
  listReports(analysisId: string): Promise<AnalysisReportResponse[]>;
  createAppeal(analysisId: string, request: AppealCreateRequestV3): Promise<AppealReceiptV3>;
  getAppeal(appealId: string): Promise<AppealResponseV3>;
  listAnalysisAppeals(analysisId: string): Promise<AppealResponseV3[]>;
  getScreenshotStatus(analysisId: string): Promise<ScreenshotStatusResponseV3>;

  listAdminAppeals(query?: PageQuery<"submitted" | "under_review" | "resolved">): Promise<AppealPageV3>;
  decideAppeal(appealId: string, request: AppealDecisionRequestV3): Promise<AppealDecisionResponseV3>;
  listAdminActions(query?: PageQuery<"pending_review" | "approved" | "rejected" | "executed" | "failed">): Promise<AdminActionPageV3>;
  decideAdminAction(actionId: string, request: AdminActionDecisionRequestV3): Promise<AdminActionDecisionResponseV3>;
  listCampaigns(query?: PageQuery<"pending_review" | "confirmed" | "rejected">): Promise<CampaignPageV3>;
  getCampaign(campaignId: string): Promise<CampaignDetailV3>;
  getOperationsMetrics(from: string, to: string): Promise<OperationsMetricsResponseV3>;

  // Admin APIs for review queue
  listReviewQueueItems(): Promise<ReviewQueueItem[]>;
  startReviewQueueItem(itemId: string): Promise<void>;
  decideReviewQueueItem(itemId: string, request: ReviewQueueDecisionRequest): Promise<void>;


  // Wave 0 admin screens remain on the read-compatible v2 endpoints until
  // the reviewed-action v3 endpoints move beyond their current 501 stubs.
  listAdminCases(): Promise<AnalysisResponse[]>;
  listAdminReports(): Promise<AnalysisReportResponse[]>;
  listAdminDecisions(): Promise<AdminDecisionAudit[]>;
  listAdminBlacklist(): Promise<BlacklistEntry[]>;
  decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse>;
}
