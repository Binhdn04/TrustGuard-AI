import { AlertCircle, Check, Circle, Clock3, Minus, X } from "lucide-react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { securityLabel, statusLabel } from "@/lib/presentation/security-labels";
import type { SecurityInvestigationStepV4 } from "@/types/generated/api-v4";

function StepIcon({ status }: { status: SecurityInvestigationStepV4["status"] }) {
  if (status === "completed") return <Check className="size-3.5" />;
  if (status === "failed") return <X className="size-3.5" />;
  if (status === "skipped") return <Minus className="size-3.5" />;
  return <Circle className="size-3.5" />;
}

export function InvestigationTimelineV4({
  lifecycle,
  steps,
  errors,
  mode,
}: {
  lifecycle: SecurityCaseViewModel["lifecycle"];
  steps: SecurityCaseViewModel["steps"];
  errors: SecurityCaseViewModel["errors"];
  mode: SecurityPresentationMode;
}) {
  return (
    <section aria-labelledby="timeline-heading" className="space-y-4">
      <div>
        <p className="micro-label">Dòng thời gian kiểm tra</p>
        <h3 id="timeline-heading" className="mt-1 text-sm font-semibold">Vòng đời thực tế và trạng thái từng bước</h3>
      </div>

      <ol aria-label="Vòng đời lượt kiểm tra" className="space-y-2">
        {lifecycle.map((entry) => (
          <li key={entry.id} className="flex gap-3 rounded-xl bg-muted/45 p-3">
            <Clock3 className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs font-semibold">{securityLabel(entry.label)}</p>
                <time dateTime={entry.occurredAt} className="text-[10px] text-muted-foreground">
                  {new Date(entry.occurredAt).toLocaleString("vi-VN")}
                </time>
              </div>
              <p className="mt-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                {statusLabel(entry.status)} · {entry.source === "event" ? `thứ tự sự kiện ${entry.sequence}` : "thời điểm lượt kiểm tra"}
              </p>
            </div>
          </li>
        ))}
      </ol>

      <div className="border-t border-border/70 pt-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs font-bold">Các bước kiểm tra</p>
          <span className="text-[10px] text-muted-foreground">Ảnh chụp trạng thái — không có thời gian riêng từng bước</span>
        </div>
        {steps.length === 0 ? (
          <p className="mt-2 text-xs leading-5 text-muted-foreground">API chưa trả bước kiểm tra.</p>
        ) : (
          <ol className="mt-3 space-y-2">
            {steps.map((step, index) => (
              <li key={step.step_id} className="flex gap-3">
                <span className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-full border border-border bg-background text-muted-foreground">
                  <StepIcon status={step.status} />
                </span>
                <div className="min-w-0 flex-1 border-b border-border/55 pb-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs font-semibold">{String(index + 1).padStart(2, "0")} · {step.tool.replaceAll("_", " ")}</p>
                    <span className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground">{statusLabel(step.status)}</span>
                  </div>
                  {mode === "analyst" && (
                    <div className="mt-1 space-y-0.5 text-[10px] leading-4 text-muted-foreground">
                      <p className="break-all">Đối tượng: <span className="font-mono text-foreground">{step.target}</span></p>
                      <p>Lý do: <span className="font-mono text-foreground">{step.reason_code}</span></p>
                      <p>Phụ thuộc: <span className="font-mono text-foreground">{step.depends_on.length ? step.depends_on.join(", ") : "không có"}</span></p>
                      {step.status_reason && <p>Lý do trạng thái: <span className="font-mono text-foreground">{step.status_reason}</span></p>}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>

      {errors.length > 0 && (
        <div className="border-t border-border/70 pt-4">
          <p className="flex items-center gap-2 text-xs font-bold text-rose-700 dark:text-rose-300"><AlertCircle className="size-4" />Lỗi công cụ ({errors.length})</p>
          <ul className="mt-2 space-y-2 text-[11px] leading-5">
            {errors.map((error, index) => (
              <li key={`${error.tool}:${error.target}:${index}`} className="rounded-lg border border-rose-500/20 bg-rose-500/6 p-2.5">
                <p className="font-semibold">{error.tool} · {error.code}</p>
                <p className="text-muted-foreground">{error.message}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
