import { CheckCircle2, Circle, Clock3, XCircle } from "lucide-react";

import type { AnalysisEvent } from "@/types/analysis";

const STEP_LABELS: Record<string, string> = {
  queued: "Yêu cầu đã vào hàng đợi",
  running: "Agent bắt đầu phân tích",
  completed: "Phân tích hoàn tất",
  failed: "Phân tích thất bại",
  review_approved: "Security Admin đã phê duyệt",
  review_rejected: "Security Admin đã bác bỏ",
};

export function AnalysisEventTimeline({ events }: { events: AnalysisEvent[] }) {
  if (events.length === 0) return null;

  return (
    <section className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-7">
      <div className="flex items-center gap-3">
        <span className="grid size-9 place-items-center rounded-xl bg-cyan-50 text-cyan-700">
          <Clock3 className="size-5" />
        </span>
        <div>
          <h2 className="font-bold text-slate-950">Tiến trình xử lý</h2>
          <p className="text-xs text-slate-500">Dữ liệu trực tiếp từ analysis events API</p>
        </div>
      </div>

      <ol className="mt-5 space-y-4">
        {events.map((event, index) => {
          const failed = event.status === "failed";
          const complete = event.status === "completed" || event.step.startsWith("review_");
          const Icon = failed ? XCircle : complete ? CheckCircle2 : Circle;
          return (
            <li key={`${event.step}-${event.occurred_at}-${index}`} className="flex gap-3">
              <Icon className={`mt-0.5 size-5 shrink-0 ${failed ? "text-rose-600" : complete ? "text-emerald-600" : "text-cyan-600"}`} />
              <div>
                <p className="text-sm font-semibold text-slate-800">{STEP_LABELS[event.step] ?? event.step}</p>
                <time className="text-xs text-slate-500" dateTime={event.occurred_at}>
                  {new Date(event.occurred_at).toLocaleString("vi-VN")}
                </time>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
