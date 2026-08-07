import { AlertIcon, CheckIcon } from "@/components/ui/icons";
import type { AnalysisResponse } from "@/types/analysis";

import { EvidenceList } from "./evidence-list";
import { RecommendationCard } from "./recommendation-card";
import { RiskBanner } from "./risk-banner";

export function AnalysisResult({ result }: { result: AnalysisResponse }) {
  if (
    result.status !== "completed" ||
    result.risk_score === null ||
    result.risk_level === null ||
    result.verdict === null ||
    result.recommended_action === null ||
    result.confidence === null ||
    result.summary === null
  ) {
    return null;
  }

  return (
    <div className="space-y-5">
      <RiskBanner
        confidence={result.confidence}
        level={result.risk_level}
        score={result.risk_score}
        summary={result.summary}
        verdict={result.verdict}
      />

      <div className="grid gap-5 xl:grid-cols-[1.15fr_0.85fr]">
        <EvidenceList items={result.evidence ?? []} />
        <div className="space-y-5">
          <RecommendationCard action={result.recommended_action} />
          <section className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-7">
            <div className="flex items-center gap-3">
              <span className="grid size-9 place-items-center rounded-xl bg-slate-100 text-slate-700">
                <CheckIcon className="size-5" />
              </span>
              <h2 className="font-bold text-slate-950">Lý do đánh giá</h2>
            </div>
            <ul className="mt-4 space-y-3">
              {(result.reasons ?? []).map((reason) => (
                <li key={reason} className="flex gap-3 text-sm leading-6 text-slate-600">
                  <span className="mt-2 size-1.5 shrink-0 rounded-full bg-cyan-500" />
                  {reason}
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>

      {(result.limitations ?? []).length > 0 && (
        <section className="flex gap-4 rounded-2xl border border-amber-200 bg-amber-50 p-5">
          <AlertIcon className="mt-0.5 size-5 shrink-0 text-amber-700" />
          <div>
            <h2 className="text-sm font-bold text-amber-950">Giới hạn của kết quả</h2>
            <ul className="mt-2 space-y-1 text-sm leading-6 text-amber-900/80">
              {(result.limitations ?? []).map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </div>
        </section>
      )}

      <p className="text-center text-xs leading-5 text-slate-400">
        Kết quả hỗ trợ ra quyết định, không phải cam kết an toàn tuyệt đối. Mã phiên: {result.analysis_id.slice(0, 8)}
      </p>
    </div>
  );
}
