"use client";

import { useEffect, useState } from "react";
import type { AnalysisReportResponse } from "@/types/analysis";
import { getAnalysisApi } from "@/lib/api/analysis-api";

export function AnalysisReportForm({ analysisId }: { analysisId: string }) {
  const [reason, setReason] = useState("Kết quả hoặc bằng chứng chưa phù hợp");
  const [comment, setComment] = useState("");
  const [status, setStatus] = useState<"idle" | "submitting" | "sent" | "error" | "loading">("loading");
  const [report, setReport] = useState<AnalysisReportResponse | null>(null);

  useEffect(() => {
    getAnalysisApi()
      .listReports(analysisId)
      .then((reports) => {
        if (reports && reports.length > 0) {
          setReport(reports[0]);
          setStatus("sent");
        } else {
          setStatus("idle");
        }
      })
      .catch(() => {
        setStatus("idle");
      });
  }, [analysisId]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (status === "submitting" || status === "sent") return;
    setStatus("submitting");
    try {
      const response = await getAnalysisApi().reportAnalysis(analysisId, {
        reason,
        comment: comment.trim() || undefined,
      });
      setReport({ ...response, status: "submitted" } as unknown as AnalysisReportResponse);
      setStatus("sent");
    } catch {
      setStatus("error");
    }
  };

  if (status === "loading") {
    return (
      <div className="mx-auto max-w-3xl rounded-xl border border-border bg-card p-5">
        <p className="text-sm">Đang tải...</p>
      </div>
    );
  }

  if (report) {
    const statusLabels: Record<string, string> = {
      submitted: "Đã gửi",
      reviewing: "Đang xem xét",
      processed: "Đã xử lý",
    };
    return (
      <div className="mx-auto max-w-3xl rounded-xl border border-border bg-card p-5">
        <h2 className="text-sm font-bold">Báo cáo kết quả</h2>
        <p className="mt-2 text-sm">Bạn đã gửi báo cáo cho phân tích này.</p>
        <p className="mt-1 text-sm font-medium">Trạng thái: <span className="text-blue-600">{statusLabels[report.status] || report.status}</span></p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-3xl rounded-xl border border-border bg-card p-5">
      <h2 className="text-sm font-bold">Báo cáo kết quả cần xem lại</h2>
      <label className="mt-4 block text-xs font-medium" htmlFor="report-reason">Lý do</label>
      <input
        id="report-reason"
        required
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        className="mt-1 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
      />
      <label className="mt-3 block text-xs font-medium" htmlFor="report-comment">Ghi chú (không bắt buộc)</label>
      <textarea
        id="report-comment"
        value={comment}
        onChange={(event) => setComment(event.target.value)}
        className="mt-1 min-h-20 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
      />
      <div className="mt-3 flex items-center gap-3">
        <button
          type="submit"
          disabled={status === "submitting" || status === "sent"}
          className="rounded-lg border border-border px-4 py-2 text-sm font-semibold hover:bg-muted disabled:opacity-50"
        >
          {status === "submitting" ? "Đang gửi…" : status === "sent" ? "Đã gửi báo cáo" : "Gửi báo cáo"}
        </button>
        {status === "error" && <p role="alert" className="text-xs text-rose-600">Không thể gửi báo cáo. Hãy thử lại.</p>}
      </div>
    </form>
  );
}
