"use client";

import { useState, type FormEvent } from "react";
import { Flag } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";

const REASONS = [
  "Kết quả đánh giá chưa chính xác",
  "Hệ thống bỏ sót dấu hiệu rủi ro",
  "Evidence không phù hợp",
  "Lý do khác",
];

export function AnalysisReportForm({ analysisId }: { analysisId: string }) {
  const [reason, setReason] = useState(REASONS[0]);
  const [comment, setComment] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [receiptId, setReceiptId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const trimmedComment = comment.trim();
      const receipt = await getAnalysisApi().reportAnalysis(analysisId, {
        reason,
        ...(trimmedComment ? { comment: trimmedComment } : {}),
      });
      setReceiptId(receipt.report_id);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không gửi được báo cáo.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-7">
      <div className="flex items-center gap-3">
        <span className="grid size-9 place-items-center rounded-xl bg-rose-50 text-rose-700"><Flag className="size-5" /></span>
        <div>
          <h2 className="font-bold text-slate-950">Báo cáo kết quả</h2>
          <p className="text-xs text-slate-500">Gửi phản hồi nếu kết quả cần được kiểm tra lại</p>
        </div>
      </div>

      {receiptId ? (
        <p role="status" className="mt-4 rounded-xl bg-emerald-50 p-4 text-sm text-emerald-800">
          Đã tiếp nhận báo cáo. Mã báo cáo: <strong>{receiptId.slice(0, 8)}</strong>
        </p>
      ) : (
        <form onSubmit={submit} className="mt-5 space-y-4">
          <div>
            <label htmlFor="report-reason" className="text-sm font-semibold text-slate-800">Lý do</label>
            <select id="report-reason" value={reason} onChange={(event) => setReason(event.target.value)} disabled={submitting} className="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm">
              {REASONS.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="report-comment" className="text-sm font-semibold text-slate-800">Mô tả thêm <span className="font-normal text-slate-400">(không bắt buộc)</span></label>
            <textarea id="report-comment" value={comment} onChange={(event) => setComment(event.target.value)} disabled={submitting} maxLength={1000} rows={3} className="mt-2 w-full resize-y rounded-xl border border-slate-200 px-3 py-2 text-sm" placeholder="Mô tả điểm chưa chính xác hoặc evidence cần bổ sung…" />
          </div>
          {error && <p role="alert" className="text-sm text-rose-700">{error}</p>}
          <button type="submit" disabled={submitting} className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-semibold text-rose-800 disabled:opacity-50">
            {submitting ? "Đang gửi…" : "Gửi báo cáo"}
          </button>
        </form>
      )}
    </section>
  );
}
