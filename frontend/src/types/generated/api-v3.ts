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

export type AnalysisCreateRequestV3 = AnalysisCreateRequest & {
  consent_to_capture_screenshot?: boolean;
};

export interface AnalysisAcceptedResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  analysis_id: string;
  status: "queued";
  created_at: string;
}

export type AnalysisResponseV3 = Omit<AnalysisResponse, "contract_version"> & {
  contract_version: typeof CONTRACT_VERSION_V3;
};

export type ScreenshotStatusV3 = "not_requested" | "pending" | "ready" | "failed" | "expired";

export interface ScreenshotArtifactV3 {
  artifact_id: string;
  media_type: "image/png" | "image/jpeg" | "image/webp";
  size_bytes: number;
  sha256: string;
  created_at: string;
  expires_at: string;
  access_path: string;
  access_expires_at: string;
}

export interface ScreenshotStatusResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  analysis_id: string;
  consented: boolean;
  status: ScreenshotStatusV3;
  artifact: ScreenshotArtifactV3 | null;
  failure_code: string | null;
}

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

export interface AppealReceiptV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  appeal_id: string;
  analysis_id: string;
  status: "submitted";
  created_at: string;
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

export interface AppealAdminRecordV3 extends AppealResponseV3 {
  owner_id: string;
}

export interface AppealPageV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  items: AppealAdminRecordV3[];
  total: number;
  limit: number;
  offset: number;
}

export interface AppealDecisionRequestV3 {
  outcome: AppealOutcomeV3;
  note: string;
}

export interface AppealDecisionResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  appeal_id: string;
  decision_id: string;
  outcome: AppealOutcomeV3;
  decided_at: string;
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

export type ReviewDecisionV3 = "approved" | "rejected";

export interface AdminActionRecordV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  action_id: string;
  analysis_id: string | null;
  campaign_id: string | null;
  action: ReviewedActionV3;
  target: string | null;
  status: AdminActionStatusV3;
  evidence_snapshot: import("@/types/analysis").Evidence[];
  proposed_at: string;
  reviewer_id: string | null;
  review_note: string | null;
  reviewed_at: string | null;
}

export interface AdminActionPageV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  items: AdminActionRecordV3[];
  total: number;
  limit: number;
  offset: number;
}

export interface AdminActionDecisionRequestV3 {
  decision: ReviewDecisionV3;
  note: string;
}

export interface AdminActionDecisionResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  action_id: string;
  decision_id: string;
  action: ReviewedActionV3;
  status: "approved" | "rejected";
  reviewed_at: string;
}

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

export interface CampaignDetailV3 extends CampaignSummaryV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  evidence_refs: string[];
  registrable_domains: string[];
  redirect_targets: string[];
  reviewer_id: string | null;
  review_note: string | null;
  reviewed_at: string | null;
}

export interface CampaignPageV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  items: CampaignSummaryV3[];
  total: number;
  limit: number;
  offset: number;
}

export interface CampaignDecisionRequestV3 {
  decision: "confirmed" | "rejected";
  note: string;
}

export type SourceTierV3 = "A" | "B" | "C" | "UNTRUSTED";

export interface SourcePolicyCreateRequestV3 {
  publisher: string;
  normalized_pattern: string;
  tier: SourceTierV3;
  source_type: string;
  explicit_deny: boolean;
  trusted_claim_review: boolean;
  allowed_operations: Array<"search" | "read" | "compare" | "promote">;
  policy_version: string;
  effective_from: string;
  effective_to: string | null;
  default_freshness_seconds: number;
}

export interface SourcePolicyRecordV3 extends SourcePolicyCreateRequestV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  source_id: string;
  active: boolean;
  reviewer_id: string;
  reviewed_at: string;
}

export interface CapabilitiesResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  profile: "offline" | "partial" | "live";
  capabilities: Record<string, "ready" | "degraded" | "not_configured">;
}

export interface OperationsMetricsResponseV3 {
  contract_version: typeof CONTRACT_VERSION_V3;
  window: { started_at: string; ended_at: string };
  generated_at: string;
  latency: Array<{
    operation: string;
    count: number;
    p50_ms: number | null;
    p95_ms: number | null;
    p99_ms: number | null;
  }>;
  cache: Array<{
    provider: string;
    hits: number;
    misses: number;
    hit_rate: number | null;
  }>;
  usage: Array<{
    provider: string;
    model: string | null;
    calls: number;
    tokens: number;
    estimated_cost_usd: number;
    quota_used: number | null;
    rate_limited: number;
    timed_out: number;
  }>;
  risk_distribution: Array<{ risk_level: RiskLevel; count: number }>;
  feedback: {
    reports: number;
    appeals: number;
    appeals_upheld: number;
    appeals_overturned: number;
    appeals_inconclusive: number;
    false_positive_rate: number | null;
  };
}
