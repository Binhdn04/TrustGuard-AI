import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";

import type { InvestigationStep } from "@/types/analysis";

const TOOL_LABELS: Record<InvestigationStep["tool"], string> = {
  local_rules: "Quy tắc cục bộ",
  blacklist_lookup: "Danh sách chặn đã duyệt",
  url_scanner: "Uy tín URL",
  redirect_resolver: "Chuỗi chuyển hướng",
  domain_intelligence: "Thông tin tên miền",
  claim_retriever: "Kho fact-check",
};

export function LiveInvestigationPlan({ steps }: { steps: InvestigationStep[] }) {
  if (steps.length === 0) return null;

  return (
    <section className="mx-auto max-w-2xl rounded-2xl border border-border bg-card p-5">
      <h2 className="font-bold">Kế hoạch điều tra trực tiếp</h2>
      <ol className="mt-4 space-y-3">
        {steps.map((step) => {
          const Icon =
            step.status === "running"
              ? Loader2
              : step.status === "completed"
                ? CheckCircle2
                : step.status === "failed"
                  ? XCircle
                  : Circle;
          return (
            <li key={step.step_id} className="flex items-start gap-3 rounded-xl bg-muted/40 p-3">
              <Icon
                aria-hidden="true"
                className={`mt-0.5 size-4 shrink-0 ${step.status === "running" ? "animate-spin text-primary" : "text-muted-foreground"}`}
              />
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold">{TOOL_LABELS[step.tool]}</span>
                  <span className="rounded-full border border-border px-2 py-0.5 text-[10px] uppercase text-muted-foreground">
                    {step.status}
                  </span>
                </div>
                <p className="mt-1 break-all text-xs text-muted-foreground">Mục tiêu: {step.target}</p>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
