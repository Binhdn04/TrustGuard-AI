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

export type PotentialThreatV4 =
  | "PHISHING"
  | "BRAND_IMPERSONATION"
  | "FINANCIAL_SCAM"
  | "RECRUITMENT_SCAM"
  | "PROMOTION_PRIZE_SCAM"
  | "CREDENTIAL_THEFT"
  | "IMPERSONATION_FINANCIAL_SCAM"
  | "CREDENTIAL_AND_OTP_PHISHING"
  | "RECRUITMENT_IMPERSONATION"
  | "CHARITY_IMPERSONATION_SCAM"
  | "INVESTMENT_IMPERSONATION_SCAM"
  | "ADVANCE_FEE_TASK_SCAM"
  | "PAYMENT_AND_OTP_PHISHING"
  | "ADVANCE_FEE_SCAM"
  | "UNDETERMINED_SECURITY_THREAT";

export type RequestedActionV4 =
  | "login"
  | "share_otp"
  | "share_credentials"
  | "transfer_money"
  | "pay_fee"
  | "provide_personal_information"
  | "open_link"
  | "install_app"
  | "share_screen"
  | "scan_qr";

export type SecurityScenarioV4 =
  | "recruitment"
  | "promotion_prize"
  | "charity"
  | "investment"
  | "online_task"
  | "account_verification"
  | "payment"
  | "refund"
  | "unknown";

export type SecurityRecommendedActionV4 =
  | "DO_NOT_OPEN_LINK"
  | "DO_NOT_SHARE_CREDENTIALS"
  | "DO_NOT_SHARE_OTP"
  | "DO_NOT_TRANSFER_MONEY"
  | "VERIFY_VIA_OFFICIAL_CHANNEL"
  | "CHANGE_PASSWORD_IF_ALREADY_SHARED"
  | "CONTACT_BANK_IF_ALREADY_PAID"
  | "REPORT_AND_BLOCK_SENDER"
  | "PROCEED_WITH_CAUTION"
  | "CLOSE_PAGE_AND_DO_NOT_RETURN"
  | "CHANGE_PASSWORD_FROM_TRUSTED_DEVICE"
  | "REVOKE_ACTIVE_SESSIONS"
  | "CONTACT_BANK_OR_PAYMENT_PROVIDER"
  | "PRESERVE_MESSAGE_FOR_REPORTING";

export type AssistantGenerationModeV4 = "ai" | "policy_grounded" | "template_fallback";
export type AssistantProcessingModeV4 = "hybrid" | "rules_only" | "fallback";
export type ExposureStateV4 = "PRE_ACTION" | "LINK_OPENED" | "CREDENTIAL_SHARED" | "OTP_SHARED" | "PAYMENT_SENT" | "UNKNOWN";
export type MissingInformationSlotV4 = "action_taken" | "requested_sensitive_action" | "url_or_contact" | "claimed_organization" | "amount_deadline_channel";

export type SecurityAnalysisStatusV4 = "queued" | "running" | "completed" | "failed";
export type SecurityConversationStatusV4 = "active" | "expired";
export type SecurityInvestigationStepStatusV4 = "pending" | "completed" | "skipped" | "failed";
export type SecurityInvestigationStatusV4 = "not_started" | "completed" | "partial";

export type SecurityInvestigationToolV4 =
  | "security_context_analysis"
  | "local_url_rules"
  | "blacklist_lookup"
  | "dns"
  | "redirect_resolver"
  | "rdap"
  | "url_reputation"
  | "brand_match"
  | "whitelist_lookup"
  | "official_claim_verifier"
  | "security_memory_lookup";

export type SecurityEvidenceTypeV4 =
  | "security_context"
  | "local_url_rule"
  | "blacklist"
  | "dns"
  | "redirect"
  | "rdap"
  | "url_reputation"
  | "brand_match"
  | "whitelist"
  | "official_verification"
  | "reviewed_security_memory";

export type TrustLifecycleV4 = "active" | "disabled";
export type WhitelistScopeV4 = "domain" | "url" | "contact";
export type OfficialVerificationPurposeV4 =
  | "verify_official_campaign"
  | "verify_brand_announcement"
  | "verify_recruitment_program"
  | "verify_official_domain"
  | "verify_official_contact";
export type OfficialVerificationVerdictV4 =
  | "OFFICIAL_CONFIRMED"
  | "OFFICIAL_CONTRADICTED"
  | "NOT_FOUND"
  | "INSUFFICIENT_EVIDENCE";
export type SecurityReportStatusV4 = "submitted" | "reviewing" | "processed";
export type SecurityReportReviewDecisionV4 = "approved" | "rejected" | "dismissed";
export type SecurityAppealStatusV4 = "submitted" | "under_review" | "resolved";
export type SecurityAppealOutcomeV4 = "uphold" | "overturn" | "inconclusive";
export type SecurityAuditResourceV4 = "brand" | "whitelist" | "memory" | "campaign" | "report" | "appeal" | "copilot";
export type SecurityAdminCopilotDispositionV4 = "confirm_malicious" | "confirm_safe" | "mark_false_positive" | "needs_more_information" | "no_change";
export type SecurityAdminCopilotActionV4 = "add_to_blacklist" | "block_domain" | "publish_broad_warning" | "none";

export interface SecurityAdminCopilotRequestV4 { refresh: boolean; }
export interface SecurityAdminCopilotRationaleV4 { text: string; evidence_refs: string[]; }
export interface SecurityAdminCopilotCampaignV4 { campaign_id: string; hypothesis: string; reviewed_at: string; evidence_refs: string[]; }
export interface SecurityAdminCopilotUsageV4 { input_tokens: number; output_tokens: number; cost_usd: number; status: "ok" | "policy_grounded" | "fallback"; }
export interface SecurityAdminCopilotResponseV4 {
  contract_version: "v4";
  suggestion_id: string;
  analysis_id: string;
  evidence_summary: string;
  conflicts: string[];
  missing_information: string[];
  related_reviewed_campaigns: SecurityAdminCopilotCampaignV4[];
  proposed_disposition: SecurityAdminCopilotDispositionV4;
  proposed_admin_action: SecurityAdminCopilotActionV4;
  action_executable: boolean;
  executed: false;
  grounded_rationale: SecurityAdminCopilotRationaleV4[];
  evidence_refs: string[];
  provider: string | null;
  model: string | null;
  suggestion_version: "security-admin-copilot-v1";
  generation_mode: AssistantGenerationModeV4;
  usage: SecurityAdminCopilotUsageV4;
  generated_at: string;
}

export interface SecurityPageV4<T> {
  contract_version: "v4";
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface SecurityConsentV4 {
  external_url_lookup: boolean;
  official_source_lookup: boolean;
}

export interface SecurityCapabilitiesResponseV4 {
  contract_version: "v4";
  product_profile: "security_triage_vnext";
  release_profile: "pre_cutover" | "cutover";
  conversation_resume: true;
  admin_feedback_review: true;
  intelligence_explorer: true;
  unified_v4_audit: true;
  admin_action_contract: "v3";
  executable_admin_actions: string[];
  deferred_admin_actions: string[];
  compatibility_contracts: Array<"v2" | "v3" | "v4">;
  security_ai_understanding?: true;
  security_ai_planning?: true;
  security_ai_explanation?: true;
  security_async_execution?: true;
  security_memory_retrieval?: true;
  security_admin_copilot?: true;
}

export interface BrandCreateRequestV4 {
  name: string;
  aliases?: string[];
  official_domains: string[];
  official_contacts?: string[];
  provenance: string;
  policy_version?: string;
  effective_from: string;
  effective_until?: string | null;
}

export interface BrandRecordV4 {
  brand_id: string;
  name: string;
  aliases: string[];
  official_domains: string[];
  official_contacts: string[];
  provenance: string;
  policy_version: string;
  effective_from: string;
  effective_until: string | null;
  lifecycle: TrustLifecycleV4;
  reviewer_id: string;
  created_at: string;
}

export type BrandPageV4 = SecurityPageV4<BrandRecordV4>;

export interface WhitelistCreateRequestV4 {
  indicator: string;
  scope: WhitelistScopeV4;
  provenance: string;
  policy_version?: string;
  effective_from: string;
  effective_until?: string | null;
}

export interface WhitelistRecordV4 {
  whitelist_id: string;
  indicator: string;
  scope: WhitelistScopeV4;
  provenance: string;
  policy_version: string;
  effective_from: string;
  effective_until: string | null;
  lifecycle: TrustLifecycleV4;
  reviewer_id: string;
  created_at: string;
}

export type WhitelistPageV4 = SecurityPageV4<WhitelistRecordV4>;

export interface OfficialSourceFindingV4 {
  source_url: string;
  finding: "confirmed" | "contradicted";
  title: string;
  observed_at: string;
}

export interface OfficialVerificationResultV4 {
  verdict: OfficialVerificationVerdictV4;
  purpose: OfficialVerificationPurposeV4;
  sources_checked: number;
  search_queries_used: number;
  evidence_refs: string[];
}

export interface SecurityTriageCreateRequestV4 {
  message: string;
  consent?: Partial<SecurityConsentV4>;
  execution_mode?: "inline" | "async";
  conversation_id?: string;
  conversation_version?: number;
}

export interface SecurityContextV4 {
  schema_version: "security-context-v1";
  claimed_entity: string | null;
  scenario: SecurityScenarioV4;
  requested_action: RequestedActionV4 | null;
  amount: string | null;
  urgency: boolean;
  urls: string[];
  credential_request: boolean;
  otp_request: boolean;
  payment_request: boolean;
  personal_information_request: boolean;
  impersonation_signals: string[];
  potential_threat: PotentialThreatV4;
}

export interface AssistantSourceSpanV4 {
  field_name: string;
  start: number;
  end: number;
}

export interface AssistantContextV4 {
  processing_mode: AssistantProcessingModeV4;
  sender_intent?: string | null;
  social_engineering_techniques: string[];
  exposure_state: ExposureStateV4;
  missing_information: string[];
  field_confidences: Record<string, number>;
  source_spans: AssistantSourceSpanV4[];
  understanding_version: "security-understanding-v1";
  model_version: string;
}

export interface SecurityConversationSummaryV4 {
  security_context: SecurityContextV4 | null;
  assistant_context?: AssistantContextV4 | null;
  unresolved_slots?: MissingInformationSlotV4[];
  evidence_refs: string[];
}

export interface SecurityConversationV4 {
  contract_version: "v4";
  conversation_id: string;
  status: SecurityConversationStatusV4;
  active_analysis_id: string;
  summary: SecurityConversationSummaryV4;
  context_version: number;
  created_at: string;
  updated_at: string;
  expires_at: string;
}

export interface SecurityInvestigationStepV4 {
  step_id: string;
  tool: SecurityInvestigationToolV4;
  target: string;
  reason_code: string;
  depends_on: string[];
  status: SecurityInvestigationStepStatusV4;
  status_reason: string | null;
}

export interface SecurityEvidenceV4 {
  evidence_ref: string;
  type: SecurityEvidenceTypeV4;
  source: string;
  target: string | null;
  signal: string;
  description: string;
  observed_at: string;
  confidence: number | null;
  provenance_ref: string | null;
}

export interface SecurityToolErrorV4 {
  tool: SecurityInvestigationToolV4;
  target: string;
  code: string;
  message: string;
  retryable: boolean;
  provider: string | null;
}

export interface AssistantReasonV4 {
  text: string;
  evidence_refs: string[];
}

export interface AssistantImmediateStepV4 {
  action: SecurityRecommendedActionV4;
  policy_ref: string;
}

export interface AssistantResponseV4 {
  summary: string;
  top_reasons: AssistantReasonV4[];
  uncertainties: string[];
  immediate_steps: AssistantImmediateStepV4[];
  follow_up_offer: string | null;
  response_version: "security-assistant-response-v1";
  generation_mode: AssistantGenerationModeV4;
}

export interface SecurityScopeResponseV4 {
  contract_version: "v4";
  analysis_id: string;
  conversation_id: string;
  conversation_version: number;
  status: SecurityAnalysisStatusV4;
  scope_decision: SecurityScopeDecisionV4;
  terminal: boolean;
  next_step: "END" | "INVESTIGATION" | "RISK_ASSESSMENT";
  scope_reasons: string[];
  security_context: SecurityContextV4 | null;
  assistant_context?: AssistantContextV4 | null;
  follow_up_question: string | null;
  follow_up_slot?: MissingInformationSlotV4 | null;
  boundary_message: string | null;
  limitations: string[];
  investigation_status: SecurityInvestigationStatusV4;
  investigation_plan: SecurityInvestigationStepV4[];
  evidence: SecurityEvidenceV4[];
  errors: SecurityToolErrorV4[];
  tool_calls_used: number;
  risk: SecurityRiskV4 | null;
  score: number | null;
  confidence: number | null;
  threat_type: PotentialThreatV4 | null;
  policy_version: string | null;
  recommended_actions: SecurityRecommendedActionV4[];
  explanation: string | null;
  explanation_evidence_refs: string[];
  assistant_response?: AssistantResponseV4 | null;
  created_at: string;
  completed_at: string | null;
}

export interface SecurityAnalysisEventV4 {
  event_id: string;
  analysis_id: string;
  sequence: number;
  status: SecurityAnalysisStatusV4;
  step: string;
  kind: "status" | "provisional" | "progress" | "final";
  step_id: string | null;
  message: string | null;
  evidence_refs: string[];
  risk_hint: SecurityRiskV4 | null;
  occurred_at: string;
}

export interface SecurityAnalysisEventPageV4 {
  contract_version: "v4";
  events: SecurityAnalysisEventV4[];
  next_cursor: string | null;
}

export interface SecurityAnalysisAcceptedResponseV4 {
  contract_version: "v4";
  analysis_id: string;
  conversation_id: string;
  conversation_version: number;
  status: "queued";
  created_at: string;
}

export interface SecurityWebSocketTicketRequestV4 {
  analysis_id: string;
}

export interface SecurityWebSocketTicketResponseV4 {
  contract_version: "v4";
  ticket: string;
  analysis_id: string;
  expires_at: string;
  stream_path: string;
  single_use: true;
}

export interface SecurityReportCreateRequestV4 {
  reason: string;
  comment?: string | null;
}

export interface SecurityReportRecordV4 {
  contract_version: "v4";
  report_id: string;
  analysis_id: string;
  reason: string;
  comment: string | null;
  status: SecurityReportStatusV4;
  decision: SecurityReportReviewDecisionV4 | null;
  reviewer_id: string | null;
  review_note: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface SecurityReportDecisionRequestV4 {
  decision: SecurityReportReviewDecisionV4;
  note: string;
}

export interface SecurityReportAdminRecordV4 extends SecurityReportRecordV4 {
  owner_id: string;
}

export type SecurityReportPageV4 = SecurityPageV4<SecurityReportAdminRecordV4>;

export interface SecurityAppealRecordV4 {
  contract_version: "v4";
  appeal_id: string;
  analysis_id: string;
  status: SecurityAppealStatusV4;
  reason: string;
  comment: string | null;
  outcome: SecurityAppealOutcomeV4 | null;
  resolution_note: string | null;
  reviewer_id: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface SecurityAppealCreateRequestV4 {
  reason: string;
  comment?: string | null;
}

export interface SecurityAppealDecisionRequestV4 {
  outcome: SecurityAppealOutcomeV4;
  note: string;
}

export interface SecurityAppealAdminRecordV4 extends SecurityAppealRecordV4 {
  owner_id: string;
}

export type SecurityAppealPageV4 = SecurityPageV4<SecurityAppealAdminRecordV4>;

export type SecurityAnalysisPageV4 = SecurityPageV4<SecurityScopeResponseV4>;
export type SecurityConversationPageV4 = SecurityPageV4<SecurityConversationV4>;

export type SecurityMemoryAdminVerdictV4 = "unreviewed" | "suspicious" | "malicious" | "safe" | "false_positive";
export type SecurityMemoryReviewedVerdictV4 = Exclude<SecurityMemoryAdminVerdictV4, "unreviewed">;
export type SecurityCampaignReviewerStatusV4 = "pending_review" | "confirmed" | "rejected";

export interface SecurityMemoryCorrectionRequestV4 {
  verdict: SecurityMemoryReviewedVerdictV4;
  note: string;
}

export interface SecurityMemoryRecordV4 {
  contract_version: "v4";
  memory_id: string;
  analysis_id: string;
  canonical_domains: string[];
  url_fingerprints: string[];
  redirect_targets: string[];
  claimed_brand: string | null;
  scenario: SecurityScenarioV4;
  requested_action: RequestedActionV4 | null;
  security_patterns: string[];
  lexical_features: string[];
  threat_type: PotentialThreatV4;
  risk: SecurityRiskV4;
  risk_policy_version: string;
  fingerprint_version: string;
  first_seen_at: string;
  last_seen_at: string;
  report_count: number;
  admin_verdict: SecurityMemoryAdminVerdictV4;
  evidence_refs: string[];
}

export type SecurityMemoryPageV4 = SecurityPageV4<SecurityMemoryRecordV4>;

export interface SecurityMemoryAuditRecordV4 {
  audit_id: string;
  memory_id: string;
  previous_verdict: SecurityMemoryAdminVerdictV4;
  verdict: SecurityMemoryAdminVerdictV4;
  reviewer_id: string;
  note: string;
  occurred_at: string;
  risk_policy_version: string;
  fingerprint_version: string;
  evidence_refs: string[];
}

export interface SecurityCampaignRecordV4 {
  contract_version: "v4";
  campaign_id: string;
  hypothesis: string;
  analysis_ids: string[];
  window_started_at: string;
  window_ended_at: string;
  aggregate_signals: Record<string, number>;
  reviewer_status: SecurityCampaignReviewerStatusV4;
  clustering_version: string;
  evidence_refs: string[];
  reviewer_id: string | null;
  review_note: string | null;
  reviewed_at: string | null;
  created_at: string;
}

export interface SecurityCampaignDecisionRequestV4 {
  decision: Exclude<SecurityCampaignReviewerStatusV4, "pending_review">;
  note: string;
}

export type SecurityCampaignPageV4 = SecurityPageV4<SecurityCampaignRecordV4>;

export interface SecurityCampaignAuditRecordV4 {
  audit_id: string;
  campaign_id: string;
  previous_status: SecurityCampaignReviewerStatusV4;
  status: SecurityCampaignReviewerStatusV4;
  reviewer_id: string;
  note: string;
  occurred_at: string;
  clustering_version: string;
  evidence_refs: string[];
}

export interface SecurityDomainIntelligenceV4 {
  domain: string;
  analysis_count: number;
  report_count: number;
  risk_distribution: Partial<Record<SecurityRiskV4, number>>;
  threat_distribution: Partial<Record<PotentialThreatV4, number>>;
  first_seen_at: string;
  last_seen_at: string;
  evidence_refs: string[];
}

export type SecurityDomainIntelligencePageV4 = SecurityPageV4<SecurityDomainIntelligenceV4>;

export interface SecurityThreatIntelligenceV4 {
  threat_type: PotentialThreatV4;
  analysis_count: number;
  report_count: number;
  risk_distribution: Partial<Record<SecurityRiskV4, number>>;
  domains: string[];
  first_seen_at: string;
  last_seen_at: string;
  evidence_refs: string[];
}

export type SecurityThreatIntelligencePageV4 = SecurityPageV4<SecurityThreatIntelligenceV4>;

export interface SecurityAdminAuditEventV4 {
  audit_id: string;
  resource_type: SecurityAuditResourceV4;
  resource_id: string;
  action: string;
  actor_id: string;
  note: string | null;
  occurred_at: string;
  evidence_refs: string[];
}

export type SecurityAdminAuditPageV4 = SecurityPageV4<SecurityAdminAuditEventV4>;
