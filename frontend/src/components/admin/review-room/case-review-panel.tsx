import { AlertTriangle, ClipboardCheck, Loader2, ShieldQuestion } from "lucide-react";

import { ActionRiskPanel } from "@/components/analysis/action-risk-panel";
import { EvidenceDeck } from "@/components/analysis/evidence-deck";
import { mapSecurityCaseViewModel } from "@/lib/mappers/security-case-view-model";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

import type { FeedbackReviewItem } from "./review-queue";

export function CaseReviewPanel({
  feedback,
  analysis,
  loading,
  error,
}: {
  feedback: FeedbackReviewItem | null;
  analysis: SecurityScopeResponseV4 | null;
  loading: boolean;
  error: string | null;
}) {
  if (!feedback) {
    return <section className="grid min-h-[420px] place-items-center rounded-2xl border border-dashed border-border bg-card/40 p-8 text-center"><div><ShieldQuestion className="mx-auto size-9 text-muted-foreground" /><h2 className="mt-3 font-semibold">Chọn một feedback record</h2><p className="mt-1 max-w-sm text-sm text-muted-foreground">Case detail chỉ được tải qua admin analysis API sau khi reviewer chọn record.</p></div></section>;
  }
  if (loading) return <section className="grid min-h-[420px] place-items-center rounded-2xl border border-border bg-card"><p role="status" className="inline-flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Đang tải structured case…</p></section>;
  if (error || !analysis) return <section className="grid min-h-[420px] place-items-center rounded-2xl border border-rose-500/25 bg-rose-500/5 p-8"><div role="alert" className="text-center text-sm text-rose-700 dark:text-rose-300"><AlertTriangle className="mx-auto mb-2 size-6" />{error ?? "Không có structured case detail."}</div></section>;

  const viewModel = mapSecurityCaseViewModel(analysis);
  const context = analysis.security_context;
  const feedbackRecord = feedback.record;

  return (
    <section aria-labelledby="case-review-heading" className="space-y-5">
      <header className="rounded-2xl border border-border bg-card p-5">
        <p className="micro-label">Selected {feedback.kind}</p>
        <div className="mt-2 flex items-start gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"><ClipboardCheck className="size-5" /></span>
          <div className="min-w-0">
            <h2 id="case-review-heading" className="text-lg font-bold">{feedbackRecord.reason}</h2>
            {feedbackRecord.comment && <p className="mt-1 text-sm leading-6 text-muted-foreground">{feedbackRecord.comment}</p>}
            <p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">Analysis {analysis.analysis_id} · Owner {feedbackRecord.owner_id}</p>
          </div>
        </div>
      </header>

      <div className="grid gap-5 2xl:grid-cols-[minmax(18rem,0.7fr)_minmax(22rem,1.3fr)]">
        <div className="space-y-5">
          <ActionRiskPanel viewModel={viewModel} mode="analyst" />
          <section className="rounded-2xl border border-border bg-card p-4">
            <p className="micro-label">Security context</p>
            {context ? (
              <dl className="mt-3 grid grid-cols-2 gap-3 text-xs">
                <div><dt className="text-muted-foreground">Claimed entity</dt><dd className="mt-1 font-semibold">{context.claimed_entity ?? "—"}</dd></div>
                <div><dt className="text-muted-foreground">Scenario</dt><dd className="mt-1 font-mono">{context.scenario}</dd></div>
                <div><dt className="text-muted-foreground">Requested action</dt><dd className="mt-1 font-mono">{context.requested_action ?? "—"}</dd></div>
                <div><dt className="text-muted-foreground">Potential threat</dt><dd className="mt-1 font-mono">{context.potential_threat}</dd></div>
                <div className="col-span-2"><dt className="text-muted-foreground">Flags</dt><dd className="mt-1">{[
                  context.urgency && "urgency", context.credential_request && "credential", context.otp_request && "otp", context.payment_request && "payment", context.personal_information_request && "personal-info",
                ].filter(Boolean).join(" · ") || "No boolean signal"}</dd></div>
                <div className="col-span-2"><dt className="text-muted-foreground">Redacted targets</dt><dd className="mt-1 space-y-1 font-mono">{context.urls.map((url) => <span key={url} className="block break-all">{url}</span>)}{context.urls.length === 0 && "—"}</dd></div>
              </dl>
            ) : <p className="mt-3 text-sm text-muted-foreground">Scope gate không trả SecurityContext.</p>}
          </section>
        </div>

        <div className="space-y-5">
          <section className="rounded-2xl border border-border bg-card p-4"><EvidenceDeck evidence={viewModel.evidence} mode="analyst" /></section>
          <section className="rounded-2xl border border-border bg-card p-4">
            <div className="flex items-end justify-between gap-3"><div><p className="micro-label">Investigation plan</p><h3 className="mt-1 text-sm font-semibold">Recorded steps</h3></div><span className="font-mono text-xs text-muted-foreground">{analysis.investigation_plan.length}</span></div>
            <ol className="mt-3 space-y-2">
              {analysis.investigation_plan.map((step) => <li key={step.step_id} className="rounded-xl border border-border bg-background/60 p-3 text-xs"><div className="flex flex-wrap items-center justify-between gap-2"><strong>{step.tool}</strong><span className="rounded-full bg-muted px-2 py-0.5 font-mono">{step.status}</span></div><p className="mt-1 break-all text-muted-foreground">{step.target}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{step.reason_code} · depends on {step.depends_on.join(", ") || "none"}</p>{step.status_reason && <p className="mt-1 text-amber-700 dark:text-amber-300">{step.status_reason}</p>}</li>)}
              {analysis.investigation_plan.length === 0 && <li className="rounded-xl border border-dashed border-border p-3 text-xs text-muted-foreground">No investigation step returned.</li>}
            </ol>
          </section>
          <section className="rounded-2xl border border-amber-500/25 bg-amber-500/7 p-4">
            <p className="micro-label text-amber-700 dark:text-amber-300">Limitations & tool errors</p>
            <ul className="mt-2 space-y-1.5 text-xs leading-5">
              {analysis.limitations.map((item) => <li key={item}>• {item}</li>)}
              {analysis.errors.map((item, index) => <li key={`${item.tool}:${item.code}:${index}`}>• {item.tool}/{item.code}: {item.message}</li>)}
              {analysis.limitations.length === 0 && analysis.errors.length === 0 && <li>No limitation or tool error returned.</li>}
            </ul>
          </section>
        </div>
      </div>
    </section>
  );
}
