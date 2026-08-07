import type { AnalysisResponseV3 } from "@/types/generated/api-v3";
import type { Evidence, Verdict } from "@/types/analysis";
import type {
  AnalysisViewModel,
  ClaimResult,
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



function mapFactCheck(response: AnalysisResponseV3): FactCheckResult | null {
  if (response.status !== "completed") return null;

  const claims = (response.claims ?? []).map<ClaimResult>((claim, index) => ({
    id: `${response.analysis_id}:claim:${index}`,
    text: claim,
    stance: "unrated",
    confidence: null,
    explanation: "Chưa có dữ liệu đánh giá chi tiết cho claim này.",
    sources: [],
  }));

  return {
    overallStance: "unrated",
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
