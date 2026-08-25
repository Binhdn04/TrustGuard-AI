import { useMemo, useState } from "react";
import { CheckCircle2, Clock3, LockKeyhole, ShieldAlert } from "lucide-react";

import type {
  SecurityAppealOutcomeV4,
  SecurityReportDecisionRequestV4,
  SecurityReportRemediationActionV4,
  SecurityReportResolutionV4,
  SecurityReportReviewDecisionV4,
  SecurityScopeResponseV4,
} from "@/types/generated/api-v4";
import { decisionLabel, statusLabel } from "@/lib/presentation/security-labels";

import { feedbackKey, type FeedbackReviewItem } from "./review-queue";

export type FeedbackDecisionSubmission =
  | { kind: "report"; request: SecurityReportDecisionRequestV4 }
  | { kind: "appeal"; decision: SecurityAppealOutcomeV4; note: string };

const resolutionLabels: Record<SecurityReportResolutionV4, string> = {
  confirm_safe: "Xác nhận an toàn",
  mark_false_positive: "Đánh dấu cảnh báo sai",
  confirm_malicious: "Xác nhận độc hại",
  needs_more_information: "Cần thêm thông tin",
  no_change: "Không thay đổi kết quả",
};

function firstCanonicalDomain(analysis: SecurityScopeResponseV4 | null): string {
  const url = analysis?.security_context?.urls[0];
  if (!url) return "";
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

export function DecisionPanel({ feedback, analysis, caseReady, busy, error, onSubmit, onBlacklistDecision }: {
  feedback: FeedbackReviewItem | null;
  analysis: SecurityScopeResponseV4 | null;
  caseReady: boolean;
  busy: boolean;
  error: string | null;
  onSubmit: (submission: FeedbackDecisionSubmission) => Promise<void>;
  onBlacklistDecision: (actionId: string, decision: "approved" | "rejected") => Promise<void>;
}) {
  const [decision, setDecision] = useState<SecurityReportReviewDecisionV4 | SecurityAppealOutcomeV4>(() => feedback?.kind === "appeal" ? "uphold" : "approved");
  const [resolution, setResolution] = useState<SecurityReportResolutionV4>("no_change");
  const [remediation, setRemediation] = useState<SecurityReportRemediationActionV4>("none");
  const [note, setNote] = useState("");
  const [indicator, setIndicator] = useState("");
  const [provenance, setProvenance] = useState("");
  const [domain, setDomain] = useState(() => firstCanonicalDomain(analysis));
  const [blacklistReason, setBlacklistReason] = useState("");
  const defaultDomain = useMemo(() => firstCanonicalDomain(analysis), [analysis]);

  if (!feedback) return null;
  const terminal = feedback.kind === "report" ? feedback.record.status === "processed" : feedback.record.status === "resolved";
  const result = feedback.kind === "report" ? feedback.record.decision : feedback.record.outcome;
  const resultNote = feedback.kind === "report" ? feedback.record.review_note : feedback.record.resolution_note;

  if (terminal) {
    const remediationStatus = feedback.kind === "report" ? feedback.record.remediation_status : null;
    const failed = remediationStatus === "failed";
    const pending = remediationStatus === "pending";
    const linkedActionId = feedback.kind === "report"
      ? feedback.record.remediation_reference?.admin_action_id
      : null;
    const tone = failed
      ? "border-rose-500/30 bg-rose-500/8"
      : pending
        ? "border-amber-500/30 bg-amber-500/8"
        : "border-emerald-500/25 bg-emerald-500/8";
    return <section className={`rounded-2xl border p-4 ${tone}`}>
      <div className="flex items-start gap-3">
        {failed
          ? <ShieldAlert className="mt-0.5 size-5 shrink-0 text-rose-600" />
          : pending
            ? <Clock3 className="mt-0.5 size-5 shrink-0 text-amber-600" />
            : <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-emerald-600" />}
        <div className="min-w-0 flex-1">
          <p className="micro-label">Quyết định đã ghi</p>
          <h3 className="mt-1 font-semibold">{decisionLabel(result)}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{resultNote ?? "Không có ghi chú."}</p>
          {feedback.kind === "report" && <div className="mt-3 rounded-xl border border-current/10 p-3 text-xs">
            <p><strong>Kết luận:</strong> {feedback.record.resolution ? resolutionLabels[feedback.record.resolution] : "Không có"}</p>
            <p className="mt-1"><strong>Khắc phục:</strong> {decisionLabel(feedback.record.remediation_action)} · {statusLabel(feedback.record.remediation_status)}</p>
            {feedback.record.remediation_reference && <p className="mt-1 break-all font-mono">{JSON.stringify(feedback.record.remediation_reference)}</p>}
          </div>}
          {pending && linkedActionId && <div className="mt-4 rounded-xl border border-amber-500/25 bg-background/70 p-3">
            <p className="text-xs font-semibold">Đề xuất chặn đang chờ quyết định riêng</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">Kiểm tra lại domain và bằng chứng trước khi thực thi. Đây là bước xác nhận của con người; hệ thống không tự động chặn.</p>
            {error && <p role="alert" className="mt-2 text-xs text-rose-700 dark:text-rose-300">{error}</p>}
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <button type="button" disabled={busy} onClick={() => void onBlacklistDecision(linkedActionId, "rejected")} className="rounded-lg border border-border px-3 py-2 text-xs font-semibold disabled:opacity-45">Từ chối đề xuất chặn</button>
              <button type="button" disabled={busy} onClick={() => void onBlacklistDecision(linkedActionId, "approved")} className="rounded-lg bg-rose-600 px-3 py-2 text-xs font-semibold text-white disabled:opacity-45">{busy ? "Đang xử lý…" : "Xác nhận thực thi chặn"}</button>
            </div>
          </div>}
          {pending && !linkedActionId && <p role="alert" className="mt-3 text-xs text-rose-700 dark:text-rose-300">Thiếu mã action liên kết; không thể thực thi đề xuất từ giao diện.</p>}
          <p className="mt-2 text-[10px] text-muted-foreground">Hồ sơ không thể được quyết định lần hai.</p>
        </div>
      </div>
    </section>;
  }

  const reportApproved = feedback.kind === "report" && decision === "approved";
  const conclusiveSafe = resolution === "confirm_safe" || resolution === "mark_false_positive";
  const conclusiveMalicious = resolution === "confirm_malicious";
  const needsWhitelist = reportApproved && remediation === "add_to_whitelist";
  const needsBlacklist = reportApproved && remediation === "propose_blacklist";
  const valid = Boolean(note.trim())
    && (!needsWhitelist || Boolean(indicator.trim() && provenance.trim()))
    && (!needsBlacklist || Boolean((domain || defaultDomain).trim() && blacklistReason.trim() && provenance.trim()));

  const changeResolution = (next: SecurityReportResolutionV4) => {
    setResolution(next);
    if (next === "needs_more_information" || next === "no_change") setRemediation("none");
    else if (next === "confirm_malicious") setRemediation("propose_blacklist");
    else setRemediation("update_memory");
  };

  const submit = () => {
    if (!valid) return;
    if (feedback.kind === "appeal") {
      void onSubmit({ kind: "appeal", decision: decision as SecurityAppealOutcomeV4, note: note.trim() });
      return;
    }
    const reportDecision = decision as SecurityReportReviewDecisionV4;
    const request: SecurityReportDecisionRequestV4 = {
      decision: reportDecision,
      resolution: reportDecision === "approved" ? resolution : undefined,
      remediation_action: reportDecision === "approved" ? remediation : "none",
      evidence_refs: analysis?.explanation_evidence_refs ?? [],
      note: note.trim(),
      ...(needsWhitelist ? { whitelist_entry: { indicator: indicator.trim(), scope: "domain", provenance: provenance.trim(), policy_version: "whitelist-v1", effective_from: new Date().toISOString(), effective_until: null } } : {}),
      ...(needsBlacklist ? { blacklist_proposal: { canonical_domain: (domain || defaultDomain).trim().toLowerCase(), reason: blacklistReason.trim(), evidence_refs: analysis?.explanation_evidence_refs.length ? analysis.explanation_evidence_refs : ["report:reviewed"], provenance: provenance.trim() } } : {}),
    };
    void onSubmit({ kind: "report", request });
  };

  const choices = feedback.kind === "report"
    ? [["approved", "Duyệt báo cáo"], ["rejected", "Từ chối báo cáo"], ["dismissed", "Bỏ qua báo cáo"]]
    : [["uphold", "Giữ nguyên"], ["overturn", "Đảo quyết định"], ["inconclusive", "Chưa đủ kết luận"]];

  return <section aria-labelledby="decision-panel-heading" className="rounded-2xl border border-border bg-card p-4">
    <div className="flex items-start gap-3"><LockKeyhole className="mt-0.5 size-5 shrink-0 text-primary" /><div><p className="micro-label">Quyết định của người duyệt</p><h3 id="decision-panel-heading" className="mt-1 font-semibold">Bắt buộc ghi căn cứ</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Nút xác nhận chỉ mở sau khi ngữ cảnh, rủi ro, bằng chứng và giới hạn đã tải thành công.</p></div></div>
    <label htmlFor={`review-decision-${feedbackKey(feedback)}`} className="mt-4 block text-xs font-semibold">Quyết định</label>
    <select id={`review-decision-${feedbackKey(feedback)}`} aria-label="Quyết định" value={decision} onChange={(event) => setDecision(event.target.value as typeof decision)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">{choices.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
    {reportApproved && <div className="mt-4 space-y-3 rounded-xl border border-border p-3">
      <label className="block text-xs font-semibold">Kết luận có cấu trúc<select aria-label="Kết luận báo cáo" value={resolution} onChange={(event) => changeResolution(event.target.value as SecurityReportResolutionV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">{Object.entries(resolutionLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      {(conclusiveSafe || conclusiveMalicious) && <label className="block text-xs font-semibold">Hành động tiếp theo<select aria-label="Hành động khắc phục" value={remediation} onChange={(event) => setRemediation(event.target.value as SecurityReportRemediationActionV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">{conclusiveSafe && <><option value="update_memory">Chỉ cập nhật Security Memory</option><option value="add_to_whitelist">Thêm vào danh sách tin cậy</option><option value="none">Không thực hiện thêm</option></>}{conclusiveMalicious && <><option value="propose_blacklist">Tạo đề xuất chặn domain</option><option value="update_memory">Chỉ cập nhật Security Memory</option><option value="none">Không thực hiện thêm</option></>}</select></label>}
      {needsWhitelist && <><label className="block text-xs font-semibold">Domain tin cậy<input aria-label="Domain thêm vào danh sách tin cậy" value={indicator} onChange={(event) => setIndicator(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="block text-xs font-semibold">Nguồn xác minh bắt buộc<textarea aria-label="Nguồn xác minh hành động khắc phục" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-16 w-full rounded-xl border border-border bg-background p-2 text-sm" /></label></>}
      {needsBlacklist && <><p className="rounded-lg bg-rose-500/8 p-2 text-xs text-rose-700">Domain chuẩn hóa dự kiến: <strong className="break-all font-mono">{domain || defaultDomain || "Chưa xác định"}</strong></p><label className="block text-xs font-semibold">Domain cần chặn<input aria-label="Domain cần chặn trong hành động khắc phục" value={domain || defaultDomain} onChange={(event) => setDomain(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 font-mono text-sm" /></label><label className="block text-xs font-semibold">Lý do chặn<textarea aria-label="Lý do chặn trong hành động khắc phục" value={blacklistReason} onChange={(event) => setBlacklistReason(event.target.value)} className="mt-1 min-h-16 w-full rounded-xl border border-border bg-background p-2 text-sm" /></label><label className="block text-xs font-semibold">Nguồn xác minh bắt buộc<textarea aria-label="Nguồn xác minh hành động khắc phục" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-16 w-full rounded-xl border border-border bg-background p-2 text-sm" /></label></>}
    </div>}
    <label htmlFor={`review-note-${feedbackKey(feedback)}`} className="mt-3 block text-xs font-semibold">Ghi chú của người duyệt</label>
    <textarea id={`review-note-${feedbackKey(feedback)}`} aria-label="Ghi chú của người duyệt" value={note} onChange={(event) => setNote(event.target.value)} placeholder="Ghi căn cứ cho lịch sử kiểm toán…" className="mt-1 min-h-24 w-full rounded-xl border border-border bg-background p-3 text-sm" />
    {error && <p role="alert" className="mt-3 rounded-xl bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">{error}</p>}
    <button type="button" disabled={!caseReady || !valid || busy} onClick={submit} className="mt-4 w-full rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-45">{busy ? "Đang ghi quyết định…" : "Xác nhận quyết định"}</button>
  </section>;
}
