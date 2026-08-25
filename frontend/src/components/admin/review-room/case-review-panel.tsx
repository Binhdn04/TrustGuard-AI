import { AlertTriangle, Bot, ChevronDown, ClipboardCheck, Loader2, RefreshCw, ShieldQuestion } from "lucide-react";

import { ActionRiskPanel } from "@/components/analysis/action-risk-panel";
import { EvidenceDeck } from "@/components/analysis/evidence-deck";
import { mapSecurityCaseViewModel } from "@/lib/mappers/security-case-view-model";
import { securityLabel, statusLabel } from "@/lib/presentation/security-labels";
import type { SecurityAdminCopilotResponseV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

import type { FeedbackReviewItem } from "./review-queue";

export function CaseReviewPanel({
  feedback,
  analysis,
  loading,
  error,
  copilot,
  copilotLoading,
  copilotError,
  onCopilot,
}: {
  feedback: FeedbackReviewItem | null;
  analysis: SecurityScopeResponseV4 | null;
  loading: boolean;
  error: string | null;
  copilot: SecurityAdminCopilotResponseV4 | null;
  copilotLoading: boolean;
  copilotError: string | null;
  onCopilot: (refresh: boolean) => void;
}) {
  if (!feedback) {
    return <section className="grid min-h-[320px] place-items-center rounded-2xl border border-dashed border-border bg-card/40 p-8 text-center"><div><ShieldQuestion className="mx-auto size-9 text-muted-foreground" /><h2 className="mt-3 font-semibold">Chọn hồ sơ để duyệt</h2><p className="mt-1 max-w-sm text-sm text-muted-foreground">Chi tiết sẽ hiển thị tại đây.</p></div></section>;
  }
  if (loading) return <section className="grid min-h-[420px] place-items-center rounded-2xl border border-border bg-card"><p role="status" className="inline-flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Đang tải hồ sơ có cấu trúc…</p></section>;
  if (error || !analysis) return <section className="grid min-h-[420px] place-items-center rounded-2xl border border-rose-500/25 bg-rose-500/5 p-8"><div role="alert" className="text-center text-sm text-rose-700 dark:text-rose-300"><AlertTriangle className="mx-auto mb-2 size-6" />{error ?? "Không có chi tiết hồ sơ có cấu trúc."}</div></section>;

  const viewModel = mapSecurityCaseViewModel(analysis);
  const context = analysis.security_context;
  const feedbackRecord = feedback.record;

  return (
    <section aria-labelledby="case-review-heading" className="space-y-5">
      <header className="rounded-2xl border border-border bg-card p-5">
        <div className="mt-2 flex items-start gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"><ClipboardCheck className="size-5" /></span>
          <div className="min-w-0">
            <h2 id="case-review-heading" className="text-lg font-bold">{feedbackRecord.reason}</h2>
            {feedbackRecord.comment && <p className="mt-1 text-sm leading-6 text-muted-foreground">{feedbackRecord.comment}</p>}
            <details className="group mt-2 text-[10px] text-muted-foreground">
              <summary className="flex cursor-pointer list-none items-center gap-1 font-semibold">Mã hồ sơ <ChevronDown className="size-3 transition-transform group-open:rotate-180" /></summary>
              <p className="mt-1 break-all font-mono">Lượt kiểm tra {analysis.analysis_id} · Chủ sở hữu {feedbackRecord.owner_id}</p>
            </details>
          </div>
        </div>
      </header>

      <div className="grid gap-5 2xl:grid-cols-[minmax(18rem,0.7fr)_minmax(22rem,1.3fr)]">
        <div className="space-y-5">
          <section aria-label="Gợi ý AI — không tự thực thi" className="rounded-2xl border border-violet-500/25 bg-violet-500/5 p-4">
            <div className="flex items-start justify-between gap-3">
              <div><h3 className="flex items-center gap-2 text-sm font-semibold"><Bot className="size-4" />Gợi ý hỗ trợ</h3><p className="mt-1 text-[11px] text-muted-foreground">Không tự thực thi</p></div>
              <button type="button" disabled={copilotLoading} onClick={() => onCopilot(copilot !== null)} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-background px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
                {copilotLoading ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}{copilot ? "Làm mới" : "Tạo gợi ý"}
              </button>
            </div>
            {copilotError && <p role="alert" className="mt-3 text-xs text-rose-700 dark:text-rose-300">{copilotError}</p>}
            {copilot && <div className="mt-4 space-y-3 text-xs">
              <p className="leading-5">{copilot.evidence_summary}</p>
              <dl className="grid gap-2 sm:grid-cols-2"><div><dt className="text-muted-foreground">Đề xuất</dt><dd className="mt-1 font-semibold">{securityLabel(copilot.proposed_disposition)}</dd></div><div><dt className="text-muted-foreground">Hành động</dt><dd className="mt-1 font-semibold">{securityLabel(copilot.proposed_admin_action)}</dd></div></dl>
              <details className="group rounded-lg border border-border bg-background/60 p-2">
                <summary className="flex cursor-pointer list-none items-center justify-between font-semibold">Căn cứ và siêu dữ liệu <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" /></summary>
                <div className="mt-2 space-y-2">
                  {copilot.grounded_rationale.map((item, index) => <div key={`${item.text}:${index}`}><p>{item.text}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{item.evidence_refs.join(" · ")}</p></div>)}
                  {(copilot.conflicts.length > 0 || copilot.missing_information.length > 0) && <p className="text-muted-foreground">Xung đột: {copilot.conflicts.join("; ") || "không"} · Thiếu: {copilot.missing_information.join("; ") || "không"}</p>}
                  {copilot.related_reviewed_campaigns.length > 0 && <p className="text-muted-foreground">Chiến dịch liên quan: {copilot.related_reviewed_campaigns.map((item) => item.hypothesis).join("; ")}</p>}
                  <p className="font-mono text-[10px] text-muted-foreground">{copilot.model ?? "theo chính sách"} · {copilot.suggestion_version}</p>
                </div>
              </details>
            </div>}
          </section>
          <ActionRiskPanel viewModel={viewModel} mode="analyst" />
          <details className="group rounded-2xl border border-border bg-card p-4">
            <summary className="flex cursor-pointer list-none items-center justify-between text-sm font-semibold">Ngữ cảnh bảo mật <ChevronDown className="size-4 transition-transform group-open:rotate-180" /></summary>
            {context ? (
              <dl className="mt-3 grid grid-cols-2 gap-3 text-xs">
                <div><dt className="text-muted-foreground">Đơn vị được nhắc đến</dt><dd className="mt-1 font-semibold">{context.claimed_entity ?? "—"}</dd></div>
                <div><dt className="text-muted-foreground">Tình huống</dt><dd className="mt-1">{securityLabel(context.scenario)}</dd></div>
                <div><dt className="text-muted-foreground">Hành động được yêu cầu</dt><dd className="mt-1">{securityLabel(context.requested_action, "—")}</dd></div>
                <div><dt className="text-muted-foreground">Nguy cơ tiềm ẩn</dt><dd className="mt-1">{securityLabel(context.potential_threat)}</dd></div>
                <div className="col-span-2"><dt className="text-muted-foreground">Tín hiệu</dt><dd className="mt-1">{[
                  context.urgency && "thúc giục", context.credential_request && "thông tin đăng nhập", context.otp_request && "OTP", context.payment_request && "thanh toán", context.personal_information_request && "thông tin cá nhân",
                ].filter(Boolean).join(" · ") || "Không có cờ ngữ cảnh"}</dd></div>
                <div className="col-span-2"><dt className="text-muted-foreground">Đối tượng đã che dữ liệu nhạy cảm</dt><dd className="mt-1 space-y-1 font-mono">{context.urls.map((url) => <span key={url} className="block break-all">{url}</span>)}{context.urls.length === 0 && "—"}</dd></div>
              </dl>
            ) : <p className="mt-3 text-sm text-muted-foreground">Không có ngữ cảnh bảo mật.</p>}
          </details>
        </div>

        <div className="space-y-5">
          <section className="rounded-2xl border border-border bg-card p-4"><EvidenceDeck evidence={viewModel.evidence} mode="analyst" /></section>
          <details className="group rounded-2xl border border-border bg-card p-4">
            <summary className="flex cursor-pointer list-none items-center justify-between text-sm font-semibold">Chi tiết kiểm tra <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">{analysis.investigation_plan.length} bước <ChevronDown className="size-4 transition-transform group-open:rotate-180" /></span></summary>
            <ol className="mt-3 space-y-2">
              {analysis.investigation_plan.map((step) => <li key={step.step_id} className="rounded-xl border border-border bg-background/60 p-3 text-xs"><div className="flex flex-wrap items-center justify-between gap-2"><strong>{step.tool}</strong><span className="rounded-full bg-muted px-2 py-0.5">{statusLabel(step.status)}</span></div><p className="mt-1 break-all text-muted-foreground">{step.target}</p><p className="mt-1 font-mono text-[10px] text-muted-foreground">{step.reason_code} · phụ thuộc {step.depends_on.join(", ") || "không có"}</p>{step.status_reason && <p className="mt-1 text-amber-700 dark:text-amber-300">{step.status_reason}</p>}</li>)}
              {analysis.investigation_plan.length === 0 && <li className="rounded-xl border border-dashed border-border p-3 text-xs text-muted-foreground">Không có bước kiểm tra.</li>}
            </ol>
          </details>
          {(analysis.limitations.length > 0 || analysis.errors.length > 0) && <details className="group rounded-2xl border border-amber-500/25 bg-amber-500/7 p-4">
            <summary className="flex cursor-pointer list-none items-center justify-between text-sm font-semibold text-amber-700 dark:text-amber-300">Giới hạn và lỗi ({analysis.limitations.length + analysis.errors.length}) <ChevronDown className="size-4 transition-transform group-open:rotate-180" /></summary>
            <ul className="mt-2 space-y-1.5 text-xs leading-5">
              {analysis.limitations.map((item) => <li key={item}>• {item}</li>)}
              {analysis.errors.map((item, index) => <li key={`${item.tool}:${item.code}:${index}`}>• {item.tool}/{item.code}: {item.message}</li>)}
            </ul>
          </details>}
        </div>
      </div>
    </section>
  );
}
