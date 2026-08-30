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
  | "scan_qr"
  | "submit_form"
  | "register_or_apply"
  | "download_file"
  | "apply_for_passport";

export type VerificationTopicV4 =
  | "recruitment" | "promotion" | "event" | "course" | "survey"
  | "account" | "payment" | "charity" | "investment" | "general_notice" | "unknown";
export type LinkRoleV4 =
  | "official_website" | "official_announcement" | "social_profile" | "application"
  | "registration" | "form" | "download" | "login" | "payment" | "contact" | "other";
export type VerificationStatusV4 = "VERIFIED" | "PARTIALLY_VERIFIED" | "UNVERIFIED" | "CONFLICTING";
export type OfficialIdentityTypeV4 =
  | "primary_website" | "website" | "domain" | "careers_page" | "social_profile" | "sub_organization";
export type OfficialIdentityMatchScopeV4 = "exact" | "host_and_subdomains" | "bounded_phrase";
export type IdentityRelationshipV4 = "official_controlled" | "parent_organization" | "endorsed_third_party_service";
export type IdentityAssociationAssuranceV4 = "discovered" | "verified" | "conflicting" | "promoted" | "rejected" | "confirmed_mismatch";
export type IdentityEvidenceFamilyV4 = "entity_self_identification" | "independent_entity_link" | "parent_declaration" | "candidate_corroboration" | "exact_resource_endorsement" | "target_resource_match" | "explicit_ownership_conflict" | "action_endorsement";
export type ResourceTypeV4 = "url" | "google_form" | "microsoft_form" | "file" | "other";
export type ResourceMatchStatusV4 = "EXACT_RESOURCE" | "EXACT_CANONICAL_URL" | "DIFFERENT_RESOURCE" | "UNRESOLVED";

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
  | "ALLOW_OPEN"
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
  | "domain_familiarity"
  | "brand_match"
  | "whitelist_lookup"
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
  | "reviewed_security_memory"
  | "domain_familiarity"
  | "official_verification";

export type TrustLifecycleV4 = "active" | "disabled";
export type WhitelistScopeV4 = "domain" | "url" | "contact";
export type SecurityBlacklistLifecycleV4 = "active" | "disabled";
export type SecurityBlacklistActionV4 = "add_to_blacklist" | "disable_blacklist";
export type SecurityBlacklistActionStatusV4 = "pending_review" | "rejected" | "executed" | "failed";
export type SecurityBlacklistReviewDecisionV4 = "approved" | "rejected";
export type SecurityReportStatusV4 = "submitted" | "reviewing" | "processed";
export type SecurityReportReviewDecisionV4 = "approved" | "rejected" | "dismissed";
export type SecurityReportResolutionV4 = "confirm_safe" | "mark_false_positive" | "confirm_malicious" | "needs_more_information" | "no_change";
export type SecurityReportRemediationActionV4 = "none" | "update_memory" | "add_to_whitelist" | "propose_blacklist";
export type SecurityReportRemediationStatusV4 = "not_requested" | "pending" | "executed" | "failed";
export type SecurityAppealStatusV4 = "submitted" | "under_review" | "resolved";
export type SecurityAppealOutcomeV4 = "uphold" | "overturn" | "inconclusive";
export type SecurityAuditResourceV4 = "brand" | "whitelist" | "memory" | "campaign" | "report" | "appeal" | "copilot" | "identity_candidate" | "blacklist";
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

export type SecurityChatRouteV4 = "conversation" | "security_analysis";

export interface SecurityChatRequestV4 {
  message: string;
  conversation_id?: string | null;
  conversation_version?: number | null;
}

export interface SecurityChatResponseV4 {
  contract_version: "v4";
  route: SecurityChatRouteV4;
  response: string;
}

export interface SecurityCapabilitiesResponseV4 {
  contract_version: "v4";
  product_profile: "security_triage_vnext";
  release_profile: "pre_cutover" | "cutover";
  conversation_resume: true;
  admin_feedback_review: true;
  intelligence_explorer: true;
  unified_v4_audit: true;
  admin_action_contract: "v4";
  executable_admin_actions: string[];
  deferred_admin_actions: string[];
  security_ai_understanding?: true;
  security_ai_planning?: true;
  security_ai_explanation?: true;
  security_async_execution?: true;
  security_memory_retrieval?: true;
  security_admin_copilot?: true;
  official_link_verification?: true;
  official_web_search_ready?: true;
  security_page_capture?: true;
  domain_familiarity?: true;
  domain_popularity_lookup_ready?: true;
}

export interface DerivedQueryProvenanceV4 {
  query_id: string;
  derived_from_fields: string[];
  transformations: string[];
}

export interface VerificationIntentV4 {
  schema_version: "verification-intent-v1";
  organization_name: string | null;
  derived_organization_names: string[];
  claim_summary: string | null;
  topic: VerificationTopicV4 | null;
  requested_action: RequestedActionV4 | null;
  action_url_indices: number[];
}

export interface OfficialIdentityV4 {
  identity_id?: string;
  identity_type: OfficialIdentityTypeV4;
  canonical_value: string;
  display_value: string;
  entity_name: string;
  match_scope?: OfficialIdentityMatchScopeV4;
  relationship?: string;
  provenance?: string;
  policy_version?: string;
  effective_from?: string | null;
  effective_until?: string | null;
  supersedes?: string | null;
  lifecycle?: TrustLifecycleV4;
  reviewed?: boolean;
  source_ref?: string | null;
}

export interface ResourceIdentityV4 {
  schema_version: "resource-identity-v1";
  resource_type: ResourceTypeV4;
  provider: string | null;
  resource_id: string | null;
  canonical_url: string | null;
  match_key: string;
}

export interface ResourceMatchV4 {
  status: ResourceMatchStatusV4;
  user_resource: ResourceIdentityV4 | null;
  official_resource: ResourceIdentityV4 | null;
  reason_code: string;
}

export interface OfficialSourceReferenceV4 {
  source_ref: string;
  identity: OfficialIdentityV4 | null;
  display_url: string;
  canonical_url: string;
  content_hash: string | null;
}

export interface OfficialLinkReferenceV4 {
  link_ref: string;
  source_ref: string;
  role: LinkRoleV4;
  display_url: string;
  canonical_url: string;
  resource: ResourceIdentityV4 | null;
}

export interface OfficialVerificationComponentV4 {
  applicable: boolean;
  status: VerificationStatusV4 | null;
  reason_code: string;
  evidence_refs: string[];
}
export interface PublisherVerificationV4 extends OfficialVerificationComponentV4 { identity: OfficialIdentityV4 | null; }
export interface ClaimVerificationV4 extends OfficialVerificationComponentV4 { topic: VerificationTopicV4 | null; }
export interface ResourceVerificationV4 extends OfficialVerificationComponentV4 { match: ResourceMatchV4 | null; }

export interface OfficialLinkVerificationReportV4 {
  schema_version: "official-link-verification-v1" | "official-link-verification-v2" | "official-link-verification-v3" | "official-link-verification-v4";
  intent: VerificationIntentV4;
  publisher_verification: PublisherVerificationV4;
  claim_verification: ClaimVerificationV4;
  resource_verification: ResourceVerificationV4;
  domain_ownership_verification?: OfficialVerificationComponentV4;
  sender_verification?: OfficialVerificationComponentV4;
  action_endorsement_verification?: OfficialVerificationComponentV4;
  overall_status: VerificationStatusV4;
  reason_code: string;
  source_refs: OfficialSourceReferenceV4[];
  link_refs: OfficialLinkReferenceV4[];
  limitations: string[];
  identity_associations?: IdentityAssociationV4[];
  identity_evidence?: IdentityEvidenceObservationV4[];
  policy_version: "official-link-verification-v1" | "official-link-verification-v2" | "official-link-verification-v3" | "official-link-verification-v4";
}

export interface IdentityEvidenceObservationV4 {
  evidence_ref: string; family: IdentityEvidenceFamilyV4; source_host: string;
  canonical_url: string; content_hash: string; observed_at: string;
}
export interface IdentityAssociationV4 {
  association_id: string; entity_name: string; canonical_url: string; canonical_domain: string;
  relationship: IdentityRelationshipV4; assurance: IdentityAssociationAssuranceV4;
  confidence: number; evidence_refs: string[]; discovered_at: string;
  verified_at: string | null; expires_at: string | null; policy_version: "identity-discovery-v2";
}
export interface IdentityCandidateV4 extends IdentityAssociationV4 {
  version: number; observations: IdentityEvidenceObservationV4[];
  supersedes: string | null; terminal_decision_id: string | null;
}
export type IdentityCandidateDecisionActionV4 = "approve" | "reject" | "confirm_mismatch";
export interface IdentityCandidateDecisionRequestV4 {
  action: IdentityCandidateDecisionActionV4; note: string; target_brand_id?: string | null;
  relationship?: IdentityRelationshipV4 | null; identity_type?: OfficialIdentityTypeV4 | null;
}
export interface ManualIdentityCandidateCreateRequestV4 {
  entity_name: string;
  identity_value: string;
  identity_type: OfficialIdentityTypeV4;
  relationship: IdentityRelationshipV4;
  source_url: string;
}
export type IdentityCandidatePageV4 = SecurityPageV4<IdentityCandidateV4>;

export interface BrandCreateRequestV4 {
  name: string;
  aliases?: string[];
  official_domains: string[];
  official_identities?: OfficialIdentityV4[];
  official_contacts?: string[];
  provenance: string;
  policy_version?: string;
  effective_from?: string;
  effective_until?: string | null;
}

export interface BrandRecordV4 {
  brand_id: string;
  name: string;
  aliases: string[];
  official_domains: string[];
  official_identities: OfficialIdentityV4[];
  official_contacts: string[];
  provenance: string;
  policy_version: string;
  effective_from: string;
  effective_until: string | null;
  supersedes: string | null;
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
  effective_from?: string;
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

export interface SecurityBlacklistProposalRequestV4 {
  canonical_domain: string;
  reason: string;
  evidence_refs: string[];
  provenance?: string | null;
  source_analysis_id?: string | null;
  source_report_id?: string | null;
}

export interface SecurityBlacklistDisableRequestV4 {
  reason: string;
  evidence_refs?: string[];
  provenance?: string | null;
}

export interface SecurityBlacklistRecordV4 {
  contract_version: "v4";
  blacklist_id: string;
  canonical_domain: string;
  lifecycle: SecurityBlacklistLifecycleV4;
  enabling_action_id: string | null;
  disabling_action_id: string | null;
  reason: string;
  provenance: string;
  evidence_refs: string[];
  created_at: string;
  updated_at: string;
  version: number;
}

export type SecurityBlacklistPageV4 = SecurityPageV4<SecurityBlacklistRecordV4>;

export interface SecurityBlacklistActionProposalV4 {
  contract_version: "v4";
  action_id: string;
  action: SecurityBlacklistActionV4;
  canonical_domain: string;
  status: SecurityBlacklistActionStatusV4;
  source_analysis_id: string | null;
  source_report_id: string | null;
  proposed_at: string;
}

export interface SecurityBlacklistDecisionRequestV4 {
  decision: SecurityBlacklistReviewDecisionV4;
  note: string;
}

export interface SecurityBlacklistDecisionResponseV4 {
  contract_version: "v4";
  action_id: string;
  action: SecurityBlacklistActionV4;
  status: SecurityBlacklistActionStatusV4;
  record: SecurityBlacklistRecordV4 | null;
  reviewed_at: string;
  executed_at: string | null;
  execution_error: string | null;
}

export interface SecurityBlacklistAuditRecordV4 {
  contract_version: "v4";
  decision_id: string;
  action_id: string;
  decision: SecurityBlacklistReviewDecisionV4;
  action: SecurityBlacklistActionV4;
  status: SecurityBlacklistActionStatusV4;
  note: string;
  evidence_refs: string[];
  decided_at: string;
  execution_error: string | null;
}

export interface SecurityTriageCreateRequestV4 {
  message: string;
  consent?: Partial<SecurityConsentV4>;
  execution_mode?: "inline" | "async";
  conversation_id?: string;
  conversation_version?: number;
}

export interface SecurityPageCaptureRequestV4 {
  url_index: number;
  external_url_lookup: true;
}

export interface SecurityContextV4 {
  schema_version: "security-context-v1" | "security-context-v2";
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
  derived_query_provenance: DerivedQueryProvenanceV4[];
  understanding_version: "security-understanding-v1" | "security-understanding-v2";
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
  domain_familiarity?: DomainFamiliarityDetailsV4 | null;
}

export type DomainFamiliarityClassificationV4 =
  | "reviewed_first_party"
  | "reviewed_platform_service"
  | "ranked_domain";

export interface DomainFamiliarityDetailsV4 {
  observed_host: string;
  registrable_domain: string;
  classification: DomainFamiliarityClassificationV4;
  platform_name: string | null;
  shared_platform: boolean;
  popularity_rank: number | null;
  popularity_bucket: number | null;
  dataset_window_end: string | null;
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
  official_verification?: OfficialLinkVerificationReportV4 | null;
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
  progress_state?: SecurityProgressStateV4 | null;
  step_id: string | null;
  message: string | null;
  evidence_refs: string[];
  risk_hint: SecurityRiskV4 | null;
  occurred_at: string;
}

export type SecurityProgressStateV4 = "started" | "completed" | "skipped" | "degraded";

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

export interface SecurityReportBlacklistProposalV4 {
  canonical_domain: string;
  reason: string;
  evidence_refs: string[];
  provenance: string;
}

export interface SecurityReportRemediationReferenceV4 {
  whitelist_id?: string | null;
  memory_id?: string | null;
  admin_action_id?: string | null;
}

export interface SecurityReportAuditDetailsV4 {
  decision: SecurityReportReviewDecisionV4;
  resolution?: SecurityReportResolutionV4 | null;
  remediation_action: SecurityReportRemediationActionV4;
  remediation_status: SecurityReportRemediationStatusV4;
  remediation_reference?: SecurityReportRemediationReferenceV4 | null;
  whitelist_entry?: WhitelistCreateRequestV4 | null;
  blacklist_proposal?: SecurityReportBlacklistProposalV4 | null;
}

export interface SecurityReportRecordV4 {
  contract_version: "v4";
  report_id: string;
  analysis_id: string;
  reason: string;
  comment: string | null;
  status: SecurityReportStatusV4;
  decision: SecurityReportReviewDecisionV4 | null;
  resolution: SecurityReportResolutionV4 | null;
  remediation_action: SecurityReportRemediationActionV4;
  whitelist_entry: WhitelistCreateRequestV4 | null;
  blacklist_proposal: SecurityReportBlacklistProposalV4 | null;
  remediation_status: SecurityReportRemediationStatusV4;
  remediation_reference: SecurityReportRemediationReferenceV4 | null;
  reviewer_id: string | null;
  review_note: string | null;
  created_at: string;
  reviewed_at: string | null;
}

export interface SecurityReportDecisionRequestV4 {
  decision: SecurityReportReviewDecisionV4;
  resolution?: SecurityReportResolutionV4 | null;
  remediation_action?: SecurityReportRemediationActionV4;
  whitelist_entry?: WhitelistCreateRequestV4 | null;
  blacklist_proposal?: SecurityReportBlacklistProposalV4 | null;
  evidence_refs?: string[];
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
  report_details?: SecurityReportAuditDetailsV4 | null;
}

export type SecurityAdminAuditPageV4 = SecurityPageV4<SecurityAdminAuditEventV4>;
