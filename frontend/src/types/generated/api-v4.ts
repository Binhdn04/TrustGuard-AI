export type SecurityScopeDecisionV4 =
  | "IN_SCOPE"
  | "NEED_MORE_INFO"
  | "OUT_OF_SCOPE_GENERAL_FACT_CHECK";

export type SecurityRiskV4 =
  | "SAFE"
  | "LOW_RISK"
  | "SUSPICIOUS"
  | "HIGH_RISK"
  | "MALICIOUS"
  | "INSUFFICIENT_EVIDENCE";

export interface SecurityConsentV4 {
  external_url_lookup: boolean;
  official_source_lookup: boolean;
}

export interface SecurityTriageCreateRequestV4 {
  message: string;
  consent?: Partial<SecurityConsentV4>;
  conversation_id?: string;
  conversation_version?: number;
}

export interface SecurityContextV4 {
  schema_version: "security-context-v1";
  claimed_entity: string | null;
  scenario: "recruitment" | "promotion_prize" | "account_verification" | "payment" | "refund" | "unknown";
  requested_action: string | null;
  amount: string | null;
  urgency: boolean;
  urls: string[];
  credential_request: boolean;
  otp_request: boolean;
  payment_request: boolean;
  personal_information_request: boolean;
  impersonation_signals: string[];
  potential_threat: string;
}

export interface SecurityInvestigationStepV4 {
  step_id: string;
  tool: string;
  target: string;
  reason_code: string;
  depends_on: string[];
  status: "pending" | "completed" | "skipped" | "failed";
  status_reason: string | null;
}

export interface SecurityEvidenceV4 {
  evidence_ref: string;
  type: string;
  source: string;
  target: string | null;
  signal: string;
  description: string;
  observed_at: string;
  confidence: number | null;
  provenance_ref: string | null;
}

export interface SecurityToolErrorV4 {
  tool: string;
  target: string;
  code: string;
  message: string;
  retryable: boolean;
  provider: string | null;
}

export interface SecurityScopeResponseV4 {
  contract_version: "v4";
  analysis_id: string;
  conversation_id: string;
  conversation_version: number;
  status: "queued" | "running" | "completed" | "failed";
  scope_decision: SecurityScopeDecisionV4;
  terminal: boolean;
  next_step: "END" | "INVESTIGATION" | "RISK_ASSESSMENT";
  scope_reasons: string[];
  security_context: SecurityContextV4 | null;
  follow_up_question: string | null;
  boundary_message: string | null;
  limitations: string[];
  investigation_status: "not_started" | "completed" | "partial";
  investigation_plan: SecurityInvestigationStepV4[];
  evidence: SecurityEvidenceV4[];
  errors: SecurityToolErrorV4[];
  tool_calls_used: number;
  risk: SecurityRiskV4 | null;
  score: number | null;
  confidence: number | null;
  threat_type: string | null;
  policy_version: string | null;
  recommended_actions: string[];
  explanation: string | null;
  explanation_evidence_refs: string[];
  created_at: string;
  completed_at: string | null;
}

export interface SecurityAnalysisEventV4 {
  event_id: string;
  analysis_id: string;
  sequence: number;
  status: "queued" | "running" | "completed" | "failed";
  step: string;
  occurred_at: string;
}

export interface SecurityAnalysisEventPageV4 {
  contract_version: "v4";
  events: SecurityAnalysisEventV4[];
  next_cursor: string | null;
}

export interface SecurityWebSocketTicketResponseV4 {
  contract_version: "v4";
  ticket: string;
  analysis_id: string;
  expires_at: string;
  stream_path: string;
  single_use: true;
}

export interface SecurityReportRecordV4 {
  contract_version: "v4";
  report_id: string;
  analysis_id: string;
  reason: string;
  comment: string | null;
  status: "submitted" | "reviewing" | "processed";
  created_at: string;
}

export interface SecurityAppealRecordV4 {
  contract_version: "v4";
  appeal_id: string;
  analysis_id: string;
  status: "submitted" | "under_review" | "resolved";
  reason: string;
  comment: string | null;
  outcome: "uphold" | "overturn" | "inconclusive" | null;
  resolution_note: string | null;
  created_at: string;
  resolved_at: string | null;
}
