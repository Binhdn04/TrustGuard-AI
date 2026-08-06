import { AlertIcon, CheckIcon, ShieldIcon } from "@/components/ui/icons";
import type { RiskLevel, Verdict } from "@/types/analysis";

const riskStyles: Record<
  RiskLevel,
  { label: string; frame: string; badge: string; bar: string }
> = {
  low: {
    label: "Rủi ro thấp",
    frame: "border-emerald-200 bg-emerald-50/70",
    badge: "bg-emerald-600 text-white",
    bar: "bg-emerald-500",
  },
  medium: {
    label: "Cần thận trọng",
    frame: "border-amber-200 bg-amber-50/70",
    badge: "bg-amber-500 text-slate-950",
    bar: "bg-amber-500",
  },
  high: {
    label: "Rủi ro cao",
    frame: "border-orange-200 bg-orange-50/70",
    badge: "bg-orange-600 text-white",
    bar: "bg-orange-500",
  },
  critical: {
    label: "Rủi ro nghiêm trọng",
    frame: "border-rose-200 bg-rose-50/80",
    badge: "bg-rose-600 text-white",
    bar: "bg-rose-600",
  },
};

const verdictLabels: Record<Verdict, string> = {
  safe: "Chưa phát hiện nguy hiểm",
  suspicious: "Có dấu hiệu đáng ngờ",
  malicious: "Có dấu hiệu độc hại",
  inconclusive: "Chưa đủ bằng chứng",
};

interface RiskBannerProps {
  confidence: number;
  level: RiskLevel;
  score: number;
  summary: string;
  verdict: Verdict;
}

export function RiskBanner({
  confidence,
  level,
  score,
  summary,
  verdict,
}: RiskBannerProps) {
  const style = riskStyles[level];
  const Icon = level === "low" ? CheckIcon : level === "medium" ? ShieldIcon : AlertIcon;

  return (
    <section className={`rounded-3xl border p-5 sm:p-7 ${style.frame}`}>
      <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex gap-4">
          <span className={`grid size-12 shrink-0 place-items-center rounded-2xl ${style.badge}`}>
            <Icon className="size-6" />
          </span>
          <div>
            <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-bold uppercase tracking-[0.08em] ${style.badge}`}>
              {style.label}
            </span>
            <h2 className="mt-3 text-xl font-bold tracking-tight text-slate-950 sm:text-2xl">
              {verdictLabels[verdict]}
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-700">{summary}</p>
          </div>
        </div>
        <div className="shrink-0 rounded-2xl bg-white/80 px-5 py-4 text-center shadow-sm">
          <p className="text-3xl font-black tabular-nums text-slate-950">
            {score}<span className="text-base font-semibold text-slate-400">/100</span>
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Độ tin cậy {Math.round(confidence * 100)}%
          </p>
        </div>
      </div>
      <div className="mt-6 h-2 overflow-hidden rounded-full bg-white/80" aria-hidden="true">
        <div className={`h-full rounded-full ${style.bar}`} style={{ width: `${score}%` }} />
      </div>
    </section>
  );
}
