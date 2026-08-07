export const CONTRACT_VERSION = "v2" as const;

export type InputType = "text" | "url" | "text_with_url";
export type AnalysisStatus = "queued" | "running" | "completed" | "failed";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type Verdict = "safe" | "suspicious" | "malicious" | "inconclusive";
export type EvidenceType =
  | "url_rule"
  | "domain_reputation"
  | "redirect"
  | "blacklist"
  | "domain_registration"
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
export type InvestigationStepStatus =
  | "pending"
  | "running"
  | "completed"
  | "skipped"
  | "failed";
export type InvestigationTool =
  | "local_rules"
  | "blacklist_lookup"
  | "url_scanner"
  | "redirect_resolver"
  | "domain_intelligence"
  | "claim_retriever";

export interface InvestigationStep {
  step_id: string;
  tool: InvestigationTool;
  target: string;
  reason_code: string;
  depends_on: string[];
  status: InvestigationStepStatus;
}

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
  investigation_plan: InvestigationStep[];
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
  step_id?: string | null;
  step_status?: InvestigationStepStatus | null;
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
  listAdminCases(): Promise<AnalysisResponse[]>;
  listAdminReports(): Promise<AnalysisReportResponse[]>;
  listAdminDecisions(): Promise<AdminDecisionAudit[]>;
  listAdminBlacklist(): Promise<BlacklistEntry[]>;
  reportAnalysis(
    analysisId: string,
    request: AnalysisReportRequest,
  ): Promise<AnalysisReportResponse>;
}
