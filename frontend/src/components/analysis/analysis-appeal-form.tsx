"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, ChevronDown, Clock3, Loader2, RefreshCw, Scale } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { AppealResponseV3 } from "@/types/generated/api-v3";

export function AnalysisAppealForm({ analysisId }: { analysisId: string }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [comment, setComment] = useState("");
  const [appeal, setAppeal] = useState<AppealResponseV3 | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const items = await getAnalysisApi().listAnalysisAppeals(analysisId);
      setAppeal(items[0] ?? null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Không thể tải trạng thái khiếu nại.");
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    void Promise.resolve().then(load);
  }, [load]);

  useEffect(() => {
    if (!appeal || appeal.status === "resolved") return;
    const timer = window.setInterval(() => void load(), 5_000);
    return () => window.clearInterval(timer);
  }, [appeal, load]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!reason.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const receipt = await getAnalysisApi().createAppeal(analysisId, {
        reason: reason.trim(),
        comment: comment.trim() || null,
      });
      setAppeal(await getAnalysisApi().getAppeal(receipt.appeal_id));
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Không thể gửi khiếu nại.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <section className="mx-auto flex max-w-3xl items-center gap-2 rounded-2xl border border-border bg-card p-5 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Đang tải trạng thái khiếu nại…</section>;
  }

  if (appeal) {
    return (
      <section className="mx-auto max-w-3xl rounded-2xl border border-violet-500/20 bg-violet-500/5 p-5" aria-live="polite">
        <div className="flex gap-3">
          {appeal.status === "resolved" ? <CheckCircle2 className="mt-0.5 size-5 shrink-0 text-emerald-600" /> : <Clock3 className="mt-0.5 size-5 shrink-0 text-violet-600" />}
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="font-semibold">{appeal.status === "resolved" ? "Khiếu nại đã được giải quyết" : appeal.status === "under_review" ? "Khiếu nại đang được xem xét" : "Đã tiếp nhận khiếu nại"}</h2>
              <button type="button" onClick={() => void load()} className="inline-flex items-center gap-1 text-xs font-semibold text-violet-700 hover:underline dark:text-violet-300"><RefreshCw className="size-3" />Làm mới</button>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              Mã hồ sơ <span className="font-mono text-foreground">{appeal.appeal_id}</span>.
            </p>
            {appeal.status !== "resolved" && <p className="mt-2 text-sm text-muted-foreground">Đội ngũ kiểm duyệt sẽ đối chiếu lại evidence snapshot trước khi đưa ra quyết định.</p>}
            {appeal.status === "resolved" && <div className="mt-4 rounded-xl border border-border bg-background/70 p-4"><p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Kết quả</p><p className="mt-1 font-semibold">{appeal.outcome === "overturn" ? "Đảo ngược kết luận trước đó" : appeal.outcome === "uphold" ? "Giữ nguyên kết luận" : "Chưa đủ bằng chứng để kết luận"}</p><p className="mt-2 text-sm text-muted-foreground">{appeal.resolution_note}</p>{appeal.resolved_at && <p className="mt-3 text-xs text-muted-foreground">Giải quyết lúc {new Date(appeal.resolved_at).toLocaleString("vi-VN")}</p>}</div>}
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-border bg-card">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center gap-3 p-5 text-left hover:bg-muted/40"
      >
        <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-violet-500/10 text-violet-600">
          <Scale className="size-4" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold">Yêu cầu xem xét lại quyết định</span>
          <span className="mt-0.5 block text-xs text-muted-foreground">Dùng khi bạn cho rằng kết luận có thể gây ảnh hưởng và cần một reviewer đánh giá lại.</span>
        </span>
        <ChevronDown className={`size-4 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <form onSubmit={submit} className="space-y-4 border-t border-border px-5 pb-5 pt-4">
          <div>
            <label htmlFor="appeal-reason" className="text-sm font-medium">Lý do khiếu nại</label>
            <input
              id="appeal-reason"
              required
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Ví dụ: Nguồn bằng chứng đã lỗi thời hoặc không áp dụng cho trường hợp này"
              className="mt-1.5 w-full rounded-xl border border-border bg-background px-3 py-2.5 text-sm outline-none focus:border-primary"
            />
            <p className="mt-1 text-right text-xs text-muted-foreground">{reason.length}/500</p>
          </div>
          <div>
            <label htmlFor="appeal-comment" className="text-sm font-medium">Thông tin bổ sung</label>
            <textarea
              id="appeal-comment"
              maxLength={5000}
              value={comment}
              onChange={(event) => setComment(event.target.value)}
              placeholder="Cung cấp bối cảnh hoặc nguồn tham khảo giúp reviewer xác minh."
              className="mt-1.5 min-h-24 w-full rounded-xl border border-border bg-background px-3 py-2.5 text-sm outline-none focus:border-primary"
            />
          </div>
          {error && <p role="alert" className="text-sm text-rose-600">{error}</p>}
          <div className="flex items-center justify-between gap-4">
            <p className="text-xs text-muted-foreground">Mỗi phân tích chỉ có thể tạo một khiếu nại đang hoạt động.</p>
            <button
              type="submit"
              disabled={!reason.trim() || submitting}
              className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50"
            >
              {submitting && <Loader2 className="size-4 animate-spin" />}
              {submitting ? "Đang gửi…" : "Gửi khiếu nại"}
            </button>
          </div>
        </form>
      )}
    </section>
  );
}
