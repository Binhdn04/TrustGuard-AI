import { useState } from "react";
import { CheckCircle2, LockKeyhole } from "lucide-react";

import type {
  SecurityAppealOutcomeV4,
  SecurityReportReviewDecisionV4,
} from "@/types/generated/api-v4";

import { feedbackKey, type FeedbackReviewItem } from "./review-queue";

export type FeedbackDecision = SecurityReportReviewDecisionV4 | SecurityAppealOutcomeV4;

export function DecisionPanel({
  feedback,
  caseReady,
  busy,
  error,
  onSubmit,
}: {
  feedback: FeedbackReviewItem | null;
  caseReady: boolean;
  busy: boolean;
  error: string | null;
  onSubmit: (decision: FeedbackDecision, note: string) => Promise<void>;
}) {
  const [decision, setDecision] = useState<FeedbackDecision>(() => feedback?.kind === "appeal" ? "uphold" : "approved");
  const [note, setNote] = useState("");

  if (!feedback) return null;
  const terminal = feedback.kind === "report" ? feedback.record.status === "processed" : feedback.record.status === "resolved";
  const result = feedback.kind === "report" ? feedback.record.decision : feedback.record.outcome;
  const resultNote = feedback.kind === "report" ? feedback.record.review_note : feedback.record.resolution_note;
  const choices: FeedbackDecision[] = feedback.kind === "report"
    ? ["approved", "rejected", "dismissed"]
    : ["uphold", "overturn", "inconclusive"];

  if (terminal) {
    return (
      <section className="rounded-2xl border border-emerald-500/25 bg-emerald-500/8 p-4">
        <div className="flex items-start gap-3"><CheckCircle2 className="mt-0.5 size-5 shrink-0 text-emerald-600" /><div><p className="micro-label text-emerald-700 dark:text-emerald-300">Terminal review</p><h3 className="mt-1 font-semibold">{result ?? "Decision recorded"}</h3><p className="mt-1 text-sm text-muted-foreground">{resultNote ?? "No reviewer note returned."}</p><p className="mt-2 text-[10px] text-muted-foreground">Record này không thể được quyết định lần hai.</p></div></div>
      </section>
    );
  }

  return (
    <section aria-labelledby="decision-panel-heading" className="rounded-2xl border border-border bg-card p-4">
      <div className="flex items-start gap-3"><LockKeyhole className="mt-0.5 size-5 shrink-0 text-primary" /><div><p className="micro-label">Reviewer decision</p><h3 id="decision-panel-heading" className="mt-1 font-semibold">Human note required</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Submit chỉ mở sau khi structured context, risk, evidence và limitations đã tải thành công.</p></div></div>
      <label htmlFor={`review-decision-${feedbackKey(feedback)}`} className="mt-4 block text-xs font-semibold">Decision</label>
      <select id={`review-decision-${feedbackKey(feedback)}`} value={decision} onChange={(event) => setDecision(event.target.value as FeedbackDecision)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">
        {choices.map((choice) => <option key={choice} value={choice}>{choice}</option>)}
      </select>
      <label htmlFor={`review-note-${feedbackKey(feedback)}`} className="mt-3 block text-xs font-semibold">Reviewer note</label>
      <textarea id={`review-note-${feedbackKey(feedback)}`} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Ghi căn cứ cho audit trail…" className="mt-1 min-h-24 w-full rounded-xl border border-border bg-background p-3 text-sm" />
      {error && <p role="alert" className="mt-3 rounded-xl bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-300">{error}</p>}
      <button type="button" disabled={!caseReady || !note.trim() || busy} onClick={() => void onSubmit(decision, note.trim())} className="mt-4 w-full rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-45">{busy ? "Đang ghi quyết định…" : "Submit reviewed decision"}</button>
    </section>
  );
}
