export const CONTRACT_VERSION = "v1" as const;

export type InputType = "text" | "url" | "text_with_url";
export type AnalysisStatus = "queued" | "running" | "completed" | "failed";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Verdict = "safe" | "suspicious" | "malicious" | "inconclusive";
export type EvidenceType =
  | "url_rule"
  | "domain_reputation"
  | "redirect"
  | "blacklist"
  | "fact_check"
  | "official_source"
  | "user_report";
export type CaseStatus =
  | "not_required"
  | "pending_review"
  | "approved"
  | "rejected";
export type RecommendedAction =
  | "allow"
  | "show_caution"
  | "do_not_open"
  | "escalate_for_review";

export interface AnalysisCreateRequest {
  message: string;
  consent_to_scan_urls: boolean;
}

export interface AnalysisAcceptedResponse {
  contract_version: typeof CONTRACT_VERSION;
  analysis_id: string;
  status: "queued";
  created_at: string;
}

export interface Evidence {
  type: EvidenceType;
  source: string;
  title: string;
  url: string | null;
  finding: string;
  observed_at: string;
}

export interface AnalysisResponse {
  contract_version: typeof CONTRACT_VERSION;
  analysis_id: string;
  status: AnalysisStatus;
  input_type: InputType | null;
  normalized_urls: string[] | null;
  claims: string[] | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  verdict: Verdict | null;
  recommended_action: RecommendedAction | null;
  confidence: number | null;
  summary: string | null;
  reasons: string[] | null;
  evidence: Evidence[] | null;
  limitations: string[] | null;
  case_status: CaseStatus | null;
  scoring_version: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface AnalysisEvent {
  analysis_id: string;
  status: AnalysisStatus;
  step: string;
  occurred_at: string;
}

export interface AnalysisReportRequest {
  reason: string;
  comment?: string;
}

export interface AnalysisReportResponse {
  report_id: string;
  analysis_id: string;
  created_at: string;
}

export interface AnalysisReportRecord extends AnalysisReportResponse {
  reporter_id: string;
  reason: string;
  comment: string | null;
}

export interface AdminDecisionRequest {
  decision: "approved" | "rejected";
  action: "add_to_blacklist" | "none";
  note: string;
}

export interface AdminDecisionResponse {
  decision_id: string;
  analysis_id: string;
  case_status: "approved" | "rejected";
  reviewed_at: string;
}

export interface AdminDecisionAudit {
  decision_id: string;
  analysis_id: string | null;
  reviewer_id: string;
  decision: "approved" | "rejected";
  action: "add_to_blacklist" | "none";
  note: string;
  decided_at: string;
}

export interface BlacklistEntry {
  domain: string;
  decision_id: string;
  added_at: string;
}

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    retryable: boolean;
    details: Record<string, unknown>;
  };
}

export interface AnalysisApi {
  createAnalysis(
    request: AnalysisCreateRequest,
  ): Promise<AnalysisAcceptedResponse>;
  getAnalysis(analysisId: string): Promise<AnalysisResponse>;
  listAnalyses(): Promise<AnalysisResponse[]>;
  getAnalysisEvents(analysisId: string): Promise<AnalysisEvent[]>;
  reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponse>;
  listAdminCases(): Promise<AnalysisResponse[]>;
  listAdminReports(): Promise<AnalysisReportRecord[]>;
  listAdminDecisions(): Promise<AdminDecisionAudit[]>;
  listAdminBlacklist(): Promise<BlacklistEntry[]>;
  decideAdminCase(
    analysisId: string,
    request: AdminDecisionRequest,
  ): Promise<AdminDecisionResponse>;
}
