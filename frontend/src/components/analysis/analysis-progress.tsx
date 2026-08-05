import { CheckIcon, ShieldIcon } from "@/components/ui/icons";
import type { AnalysisStatus } from "@/types/analysis";

const steps = [
  "Tiếp nhận yêu cầu",
  "Kiểm tra URL, domain và bằng chứng",
  "Tính điểm và tổng hợp cảnh báo",
];

export function AnalysisProgress({ status }: { status: AnalysisStatus }) {
  const current = status === "queued" ? 0 : 1;

  return (
    <section
      aria-live="polite"
      aria-label="Tiến trình phân tích"
      className="overflow-hidden rounded-3xl border border-cyan-100 bg-white shadow-[0_20px_60px_rgba(15,23,42,0.06)]"
    >
      <div className="bg-[var(--navy)] px-6 py-6 text-white sm:px-8">
        <div className="flex items-center gap-4">
          <span className="relative grid size-12 place-items-center rounded-2xl bg-white/10 text-[var(--accent)]">
            <span className="absolute inset-0 animate-ping rounded-2xl bg-cyan-400/10" />
            <ShieldIcon className="relative size-7" />
          </span>
          <div>
            <p className="font-bold">Agent đang điều tra</p>
            <p className="mt-1 text-sm text-slate-300">
              Kết quả thường có trong vài giây với dữ liệu mô phỏng.
            </p>
          </div>
        </div>
      </div>
      <ol className="space-y-0 px-6 py-5 sm:px-8">
        {steps.map((step, index) => {
          const done = index < current;
          const active = index === current;
          return (
            <li key={step} className="flex min-h-12 items-center gap-3 text-sm">
              <span
                className={`grid size-7 shrink-0 place-items-center rounded-full ${
                  done
                    ? "bg-emerald-100 text-emerald-700"
                    : active
                      ? "bg-cyan-100 text-cyan-700 ring-4 ring-cyan-50"
                      : "bg-slate-100 text-slate-400"
                }`}
              >
                {done ? (
                  <CheckIcon className="size-4" />
                ) : active ? (
                  <span className="size-2 animate-pulse rounded-full bg-current" />
                ) : (
                  index + 1
                )}
              </span>
              <span className={active ? "font-semibold text-slate-900" : "text-slate-500"}>
                {step}
              </span>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
