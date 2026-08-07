import type {
  AnalysisCreateRequest,
  AnalysisResponse,
  AnalysisStatus,
  CaseStatus,
  InvestigationStepStatus,
  InvestigationTool,
  RiskLevel,
} from "@/types/analysis";

export const CONTRACT_VERSION_V3 = "v3" as const;

export type AnalysisCreateRequestV3 = AnalysisCreateRequest;

export interface AnalysisAcceptedResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  analysis_id: string;
  status: "queued";
  created_at: string;
}

export type AnalysisResponseV3 = Omit<AnalysisResponse, "contract_version"> & {
  contract_version: typeof CONTRACT_VERSION_V3;
};

export type AnalysisEventTypeV3 =
  | "analysis_status"
  | "step_transition"
  | "provisional_warning"
  | "final_result"
  | "case_update"
  | "limitation";

interface AnalysisEventBaseV3 {
  event_id: string;
  analysis_id: string;
  sequence: number;
  event_type: AnalysisEventTypeV3;
  occurred_at: string;
}

export interface AnalysisStatusEventV3 extends AnalysisEventBaseV3 {
  event_type: "analysis_status";
  payload: { status: AnalysisStatus };
}

export interface StepTransitionEventV3 extends AnalysisEventBaseV3 {
  event_type: "step_transition";
  payload: {
    step_id: string;
    tool: InvestigationTool;
    target: string;
    reason_code: string;
    depends_on: string[];
    status: InvestigationStepStatus;
  };
}

export interface ProvisionalWarningEventV3 extends AnalysisEventBaseV3 {
  event_type: "provisional_warning";
  payload: {
    risk_level: Extract<RiskLevel, "medium" | "high" | "critical">;
    summary: string;
    evidence_refs: string[];
    is_provisional: true;
  };
}

export interface FinalResultEventV3 extends AnalysisEventBaseV3 {
  event_type: "final_result";
  payload: { result_ref: string; status: "completed" };
}

export interface CaseUpdateEventV3 extends AnalysisEventBaseV3 {
  event_type: "case_update";
  payload: { case_status: CaseStatus; decision_id: string | null };
}

export interface LimitationEventV3 extends AnalysisEventBaseV3 {
  event_type: "limitation";
  payload: { code: string; message: string; retryable: boolean };
}

export type AnalysisEventV3 =
  | AnalysisStatusEventV3
  | StepTransitionEventV3
  | ProvisionalWarningEventV3
  | FinalResultEventV3
  | CaseUpdateEventV3
  | LimitationEventV3;

export interface AnalysisEventPageV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  events: AnalysisEventV3[];
  next_cursor: string | null;
}

export interface AnalysisReportResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  report_id: string;
  analysis_id: string;
  created_at: string;
}

export interface WebSocketTicketRequestV3 {
  analysis_id: string;
}

export interface WebSocketTicketResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  ticket: string;
  analysis_id: string;
  expires_at: string;
  stream_path: string;
  single_use: true;
}

export type AppealStatusV3 = "submitted" | "under_review" | "resolved";
export type AppealOutcomeV3 = "uphold" | "overturn" | "inconclusive";

export interface AppealCreateRequestV3 {
  reason: string;
  comment?: string | null;
}

export interface AppealResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  appeal_id: string;
  analysis_id: string;
  status: AppealStatusV3;
  reason: string;
  comment: string | null;
  outcome: AppealOutcomeV3 | null;
  resolution_note: string | null;
  created_at: string;
  resolved_at: string | null;
}

export type ReviewedActionV3 =
  | "add_to_blacklist"
  | "disable_blacklist"
  | "block_domain"
  | "publish_broad_warning"
  | "none";

export type AdminActionStatusV3 =
  | "pending_review"
  | "approved"
  | "rejected"
  | "executed"
  | "failed";

export type CampaignReviewerStatusV3 =
  | "pending_review"
  | "confirmed"
  | "rejected";

export interface CampaignSummaryV3 {
  campaign_id: string;
  hypothesis: string;
  window_started_at: string;
  window_ended_at: string;
  analysis_count: number;
  aggregate_signals: Array<{ signal: string; count: number }>;
  reviewer_status: CampaignReviewerStatusV3;
  clustering_version: string;
}

export interface OperationsMetricsV3 {
  active_analyses: number;
  completed_analyses_24h: number;
  average_latency_ms: number;
  error_rate: number;
}

