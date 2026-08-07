export const CONTRACT_VERSION = "v1" as const;

export type InputType = "text" | "url" | "text_with_url";
export type ClaimStance = "supports" | "refutes" | "mixed" | "unrated";
export type LinkVerdict = "safe" | "suspicious" | "malicious" | "inconclusive";
export type LinkScanStatus =
  | "not_applicable"
  | "not_scanned"
  | "running"
  | "completed"
  | "failed";

export interface FactCheckSource {
  id: string;
  publisher: string;
  title: string;
  url: string;
  finding: string;
  relevance: number;
  observedAt: string;
  official: boolean;
}

export interface ClaimResult {
  id: string;
  text: string;
  stance: ClaimStance;
  confidence: number | null;
  explanation: string;
  sources: FactCheckSource[];
}

export interface FactCheckResult {
  overallStance: ClaimStance;
  summary: string;
  confidence: number | null;
  claims: ClaimResult[];
}

export interface UrlAssessment {
  url: string;
  normalizedUrl: string;
  verdict: LinkVerdict;
  provider: string | null;
  signals: string[];
  domainRegisteredAt: string | null;
  redirects: string[];
  observedAt: string | null;
}

export interface LinkSafetyResult {
  status: LinkScanStatus;
  overallVerdict: LinkVerdict | null;
  urls: UrlAssessment[];
  limitations: string[];
}

export interface AnalysisViewModel {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  originalContent: string;
  createdAt: string;
  completedAt: string | null;
  factCheck: FactCheckResult | null;
  linkSafety: LinkSafetyResult;
  limitations: string[];
}

// Request and Response for API

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

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    retryable: boolean;
    details: Record<string, unknown>;
  };
}

// DTOs for HTTP API matching the old structure to be transformed by adapter,
// or we just return AnalysisViewModel directly if we use the adapter pattern correctly.
// Based on the spec: "Raw backend response sau này phải được chuyển đổi trong API adapter."
// So AnalysisApi returns AnalysisViewModel.

export interface AnalysisApi {
  createAnalysis(request: AnalysisCreateRequest): Promise<AnalysisAcceptedResponse>;
  getAnalysis(analysisId: string): Promise<AnalysisViewModel>;
}
