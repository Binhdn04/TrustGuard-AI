import type { AnalysisResponseV3 } from "@/types/generated/api-v3";
import type { Evidence, Verdict } from "@/types/analysis";
import type {
  AnalysisViewModel,
  ClaimResult,
  ClaimStance,
  FactCheckResult,
  LinkSafetyResult,
} from "@/types/analysis-view-model";

const URL_PATTERN = /https?:\/\/[^\s]+/giu;

const LINK_EVIDENCE_TYPES = new Set<Evidence["type"]>([
  "url_rule",
  "domain_reputation",
  "redirect",
  "blacklist",
  "domain_registration",
]);

export interface AnalysisMappingContext {
  originalContent: string;
  consentToScanUrls: boolean;
}

function stanceFromFinding(finding: string): ClaimStance {
  const normalized = finding.trim().toLowerCase();
  if (/\b(false|refute|refuted|incorrect|misleading)\b|sai|bác bỏ|tin giả/iu.test(normalized)) {
    return "refutes";
  }
  if (/\b(mixed|partly|partially)\b|một phần|gây hiểu lầm/iu.test(normalized)) {
    return "mixed";
  }
  if (/\b(true|supported|confirmed|correct)\b|xác nhận|chính xác/iu.test(normalized)) {
    return "supports";
  }
  return "unrated";
}

function combineStances(stances: ClaimStance[]): ClaimStance {
  const rated = stances.filter((stance) => stance !== "unrated");
  if (rated.length === 0) return "unrated";
  return rated.every((stance) => stance === rated[0]) ? rated[0] : "mixed";
}

function mapFactCheck(response: AnalysisResponseV3): FactCheckResult | null {
  if (response.status !== "completed") return null;

  const factEvidence = (response.evidence ?? []).filter(
    (item) => item.type === "fact_check" || item.type === "official_source",
  );
  const overallStance = combineStances(
    factEvidence.map((item) => stanceFromFinding(item.finding)),
  );
  const sources = factEvidence
    .filter((item): item is Evidence & { url: string } => Boolean(item.url))
    .map((item, index) => ({
      id: `${response.analysis_id}:source:${index}`,
      publisher: item.source,
      title: item.title,
      url: item.url,
      finding: item.finding,
      relevance: response.confidence ?? 0,
      observedAt: item.observed_at,
      official: item.type === "official_source",
    }));

  const claims = (response.claims ?? []).map<ClaimResult>((claim, index) => ({
    id: `${response.analysis_id}:claim:${index}`,
    text: claim,
    stance: overallStance,
    confidence: response.confidence,
    explanation:
      response.reasons?.[index] ?? response.summary ?? "Chưa có giải thích cho phát biểu này.",
    sources,
  }));

  return {
    overallStance,
    summary: response.summary ?? "Chưa có bản tóm tắt kết quả.",
    confidence: response.confidence,
    claims,
  };
}

function verdictForLink(response: AnalysisResponseV3): Verdict {
  const hasLinkEvidence = (response.evidence ?? []).some((item) =>
    LINK_EVIDENCE_TYPES.has(item.type),
  );
  return hasLinkEvidence ? (response.verdict ?? "inconclusive") : "inconclusive";
}

function mapLinkSafety(
  response: AnalysisResponseV3,
  context: AnalysisMappingContext,
): LinkSafetyResult {
  const urls = response.normalized_urls ?? context.originalContent.match(URL_PATTERN) ?? [];
  if (urls.length === 0) {
    return { status: "not_applicable", overallVerdict: null, urls: [], limitations: [] };
  }
  if (!context.consentToScanUrls) {
    return {
      status: "not_scanned",
      overallVerdict: null,
      urls: [],
      limitations: ["Bạn chưa cho phép kiểm tra URL qua dịch vụ bảo mật bên ngoài."],
    };
  }
  if (response.status === "failed") {
    return {
      status: "failed",
      overallVerdict: null,
      urls: [],
      limitations: response.limitations ?? ["Không thể hoàn tất kiểm tra liên kết."],
    };
  }
  if (response.status !== "completed") {
    return { status: "running", overallVerdict: null, urls: [], limitations: [] };
  }

  const linkEvidence = (response.evidence ?? []).filter((item) =>
    LINK_EVIDENCE_TYPES.has(item.type),
  );
  const verdict = verdictForLink(response);
  const provider = linkEvidence[0]?.source ?? null;
  const observedAt = linkEvidence[0]?.observed_at ?? response.completed_at;
  return {
    status: "completed",
    overallVerdict: verdict,
    urls: urls.map((url) => ({
      url,
      normalizedUrl: url,
      verdict,
      provider,
      signals: linkEvidence.map((item) => item.finding),
      domainRegisteredAt: null,
      redirects: [],
      observedAt,
    })),
    limitations: response.limitations ?? [],
  };
}

export function mapAnalysisResponseToViewModel(
  response: AnalysisResponseV3,
  context: AnalysisMappingContext,
): AnalysisViewModel {
  return {
    id: response.analysis_id,
    status: response.status,
    originalContent: context.originalContent,
    createdAt: response.created_at,
    completedAt: response.completed_at,
    factCheck: mapFactCheck(response),
    linkSafety: mapLinkSafety(response, context),
    limitations: response.limitations ?? [],
  };
}
