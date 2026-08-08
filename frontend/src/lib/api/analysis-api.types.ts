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
  WebSocketTicketResponseV3,
} from "@/types/generated/api-v3";

export interface AnalysisEventQuery {
  cursor?: string | null;
  limit?: number;
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
