import type {
  AnalysisStatus,
  Verdict,
} from "@/types/analysis";

export type ClaimStance = "supports" | "refutes" | "mixed" | "unrated";

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

export type LinkScanStatus =
  | "not_applicable"
  | "not_scanned"
  | "running"
  | "completed"
  | "failed";

export interface UrlAssessment {
  url: string;
  normalizedUrl: string;
  verdict: Verdict;
  provider: string | null;
  signals: string[];
  domainRegisteredAt: string | null;
  redirects: string[];
  observedAt: string | null;
}

export interface LinkSafetyResult {
  status: LinkScanStatus;
  overallVerdict: Verdict | null;
  urls: UrlAssessment[];
  limitations: string[];
}

export interface AnalysisViewModel {
  id: string;
  status: AnalysisStatus;
  originalContent: string;
  createdAt: string;
  completedAt: string | null;
  factCheck: FactCheckResult | null;
  linkSafety: LinkSafetyResult;
  limitations: string[];
}

export type AnalysisUiState =
  | "idle"
  | "submitting"
  | "queued"
  | "provisional"
  | "investigating"
  | "final"
  | "failed";

export type AnalysisTransportState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "polling_fallback";
