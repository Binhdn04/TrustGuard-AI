"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Link as LinkIcon,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import { ApiError } from "@/lib/api/http-analysis-api";
import { cn } from "@/lib/utils";
import type {
  AdminDecisionRequest,
  AnalysisResponse,
  BlacklistEntry,
  ReviewQueueItem,
  ReviewQueueDecisionRequest,
} from "@/types/analysis";

interface PendingDecision {
  analysis: AnalysisResponse;
  title: string;
  request: Omit<AdminDecisionRequest, "note">;
}

function displayDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<"factcheck" | "url" | "reports">("factcheck");
  const [cases, setCases] = useState<AnalysisResponse[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([]);
  const [reports, setReports] = useState<ReviewQueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingDecision | null>(null);
  const [pendingReport, setPendingReport] = useState<{ report: ReviewQueueItem, title: string, request: Omit<ReviewQueueDecisionRequest, "note"> } | null>(null);
  const [note, setNote] = useState("");
  const [submittingIds, setSubmittingIds] = useState<Set<string>>(new Set());
  const [caseErrors, setCaseErrors] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const api = getAnalysisApi();
      const [reviewCases, blacklistEntries, reviewQueueItems] = await Promise.all([
        api.listAdminCases(),
        api.listAdminBlacklist(),
        api.listReviewQueueItems(),
      ]);
      setCases(reviewCases);
      setBlacklist(blacklistEntries);
      setReports(reviewQueueItems);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Không thể tải hàng đợi kiểm duyệt.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const api = getAnalysisApi();
    void Promise.all([api.listAdminCases(), api.listAdminBlacklist(), api.listReviewQueueItems()])
      .then(([reviewCases, blacklistEntries, reviewQueueItems]) => {
        if (!active) return;
        setCases(reviewCases);
        setBlacklist(blacklistEntries);
        setReports(reviewQueueItems);
      })
      .catch((error: unknown) => {
        if (active) setLoadError(error instanceof Error ? error.message : "Không thể tải hàng đợi kiểm duyệt.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const urlCases = useMemo(
    () => cases.filter((item) => (item.normalized_urls?.length ?? 0) > 0),
    [cases],
  );

  const openDecision = (
    analysis: AnalysisResponse,
    title: string,
    request: Omit<AdminDecisionRequest, "note">,
  ) => {
    if (submittingIds.has(analysis.analysis_id)) return;
    setPending({ analysis, title, request });
    setNote("");
  };

  const submitDecision = async () => {
    if (!pending || !note.trim() || submittingIds.has(pending.analysis.analysis_id)) return;
    const analysisId = pending.analysis.analysis_id;
    setSubmittingIds((current) => new Set(current).add(analysisId));
    setCaseErrors((current) => ({ ...current, [analysisId]: "" }));
    try {
      await getAnalysisApi().decideAdminCase(analysisId, {
        ...pending.request,
        note: note.trim(),
      });
      setCases((current) => current.filter((item) => item.analysis_id !== analysisId));
      setPending(null);
      await load();
    } catch (error) {
      const message = error instanceof ApiError && error.status === 409
        ? "Case đã được reviewer khác xử lý. Dữ liệu vừa được tải lại."
        : error instanceof Error ? error.message : "Không thể lưu quyết định.";
      setCaseErrors((current) => ({ ...current, [analysisId]: message }));
      setPending(null);
      if (error instanceof ApiError && error.status === 409) await load();
    } finally {
      setSubmittingIds((current) => {
        const next = new Set(current);
        next.delete(analysisId);
        return next;
      });
    }
  };

  const openReportDecision = (
    report: ReviewQueueItem,
    title: string,
    request: Omit<ReviewQueueDecisionRequest, "note">,
  ) => {
    if (submittingIds.has(report.item_id)) return;
    setPendingReport({ report, title, request });
    setNote("");
  };

  const submitReportDecision = async () => {
    if (!pendingReport || !note.trim() || submittingIds.has(pendingReport.report.item_id)) return;
    const itemId = pendingReport.report.item_id;
    setSubmittingIds((current) => new Set(current).add(itemId));
    try {
      await getAnalysisApi().decideReviewQueueItem(itemId, {
        ...pendingReport.request,
        note: note.trim(),
      });
      setReports((current) => current.filter((item) => item.item_id !== itemId));
      setPendingReport(null);
      await load();
    } catch (error) {
      const message = error instanceof ApiError && error.status === 409
        ? "Report đã được xử lý."
        : error instanceof Error ? error.message : "Không thể lưu quyết định.";
      alert(message);
      setPendingReport(null);
      if (error instanceof ApiError && error.status === 409) await load();
    } finally {
      setSubmittingIds((current) => {
        const next = new Set(current);
        next.delete(itemId);
        return next;
      });
    }
  };

  const startReportReview = async (itemId: string) => {
    try {
        await getAnalysisApi().startReviewQueueItem(itemId);
        await load();
    } catch (error) {
        alert("Lỗi start review");
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Admin Workspace</h1>
        <p className="mt-2 text-muted-foreground">Hàng đợi human-in-the-loop từ API; mọi quyết định đều cần ghi chú.</p>
      </div>

      <div className="mb-6 flex max-w-[600px] space-x-1 rounded-xl bg-muted p-1" role="tablist">
        <button role="tab" aria-selected={activeTab === "factcheck"} onClick={() => setActiveTab("factcheck")} className={cn("flex-1 rounded-lg px-3 py-2 text-sm font-medium", activeTab === "factcheck" ? "bg-background shadow-sm" : "text-muted-foreground")}>Fact-check Review</button>
        <button role="tab" aria-selected={activeTab === "url"} onClick={() => setActiveTab("url")} className={cn("flex-1 rounded-lg px-3 py-2 text-sm font-medium", activeTab === "url" ? "bg-background shadow-sm" : "text-muted-foreground")}>URL Security</button>
        <button role="tab" aria-selected={activeTab === "reports"} onClick={() => setActiveTab("reports")} className={cn("flex-1 rounded-lg px-3 py-2 text-sm font-medium", activeTab === "reports" ? "bg-background shadow-sm" : "text-muted-foreground")}>User Reports</button>
      </div>

      {loading && <div aria-live="polite" className="flex justify-center py-16"><Loader2 className="size-7 animate-spin text-primary" /></div>}
      {loadError && <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">{loadError}<button type="button" onClick={() => void load()} className="ml-2 font-bold underline">Thử lại</button></div>}

      {!loading && !loadError && activeTab === "factcheck" && (
        <div className="space-y-4">
          {cases.map((review) => {
            const submitting = submittingIds.has(review.analysis_id);
            return (
              <article key={review.analysis_id} className="rounded-2xl border bg-card p-5">
                <div className="flex flex-col gap-6 md:flex-row">
                  <div className="min-w-0 flex-1 space-y-4">
                    <div>
                      <h2 className="mb-1 text-xs font-semibold uppercase text-muted-foreground">Claim cần duyệt</h2>
                      <p className="text-sm font-medium">{review.claims?.join(" · ") || review.summary || review.analysis_id}</p>
                    </div>
                    <div className="rounded-xl border border-border bg-muted/50 p-3">
                      <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase text-muted-foreground"><FileText className="size-3.5" />Evidence snapshot ({review.evidence?.length ?? 0})</h3>
                      <ul className="mt-3 space-y-2">
                        {(review.evidence ?? []).map((evidence, index) => (
                          <li key={`${evidence.type}:${index}`} className="rounded-lg bg-background p-3 text-xs">
                            <p className="font-bold">{evidence.title}</p>
                            <p className="mt-1 text-muted-foreground">{evidence.source}: {evidence.finding}</p>
                            {evidence.url && <p className="mt-1 break-all text-muted-foreground">URL nguồn: {evidence.url}</p>}
                          </li>
                        ))}
                        {(review.evidence?.length ?? 0) === 0 && <li className="text-xs text-muted-foreground">Không có evidence snapshot.</li>}
                      </ul>
                    </div>
                    {(review.limitations?.length ?? 0) > 0 && <div className="flex gap-2 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-xs text-amber-700"><AlertTriangle className="size-4 shrink-0" /><span>{review.limitations?.join(" ")}</span></div>}
                    {caseErrors[review.analysis_id] && <p role="alert" className="text-sm font-medium text-rose-600">{caseErrors[review.analysis_id]}</p>}
                  </div>
                  <div className="flex shrink-0 flex-row gap-2 md:flex-col">
                    <button disabled={submitting} onClick={() => openDecision(review, "Xác nhận kết quả AI", { decision: "approved", action: "none" })} className="flex items-center justify-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-600 disabled:opacity-50"><CheckCircle2 className="size-4" />Approve</button>
                    <button disabled={submitting} onClick={() => openDecision(review, "Bác bỏ kết quả AI", { decision: "rejected", action: "none" })} className="flex items-center justify-center gap-2 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-2 text-sm font-semibold text-rose-600 disabled:opacity-50"><XCircle className="size-4" />Reject</button>
                  </div>
                </div>
              </article>
            );
          })}
          {cases.length === 0 && <div className="rounded-2xl border border-dashed py-12 text-center text-muted-foreground">Không có case đang chờ duyệt.</div>}
        </div>
      )}

      {!loading && !loadError && activeTab === "url" && (
        <div className="space-y-4">
          {urlCases.map((review) => {
            const url = review.normalized_urls?.[0] ?? "";
            const domain = displayDomain(url);
            const listed = blacklist.some((entry) => entry.domain === domain);
            const submitting = submittingIds.has(review.analysis_id);
            return (
              <article key={review.analysis_id} className="rounded-2xl border bg-card p-5">
                <div className="flex flex-col gap-6 md:flex-row">
                  <div className="min-w-0 flex-1 space-y-3">
                    <h2 className="flex items-center gap-2 text-sm font-bold"><LinkIcon className="size-4 text-muted-foreground" /><span className="break-all">{domain}</span></h2>
                    <p className="break-all rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">URL phân tích: {url}</p>
                    <p className="text-xs">Verdict: <strong>{review.verdict ?? "inconclusive"}</strong> · Blacklist: <strong>{listed ? "đã có" : "chưa có"}</strong></p>
                    <div className="rounded-xl border p-3">
                      <h3 className="text-xs font-semibold uppercase text-muted-foreground">Evidence snapshot</h3>
                      {(review.evidence ?? []).map((evidence, index) => <p key={`${evidence.type}:${index}`} className="mt-2 text-xs"><strong>{evidence.source}</strong>: {evidence.finding}</p>)}
                    </div>
                    {caseErrors[review.analysis_id] && <p role="alert" className="text-sm font-medium text-rose-600">{caseErrors[review.analysis_id]}</p>}
                  </div>
                  <div className="flex shrink-0 flex-row gap-2 md:flex-col">
                    <button disabled={submitting || listed} onClick={() => openDecision(review, `Thêm ${domain} vào blacklist`, { decision: "approved", action: "add_to_blacklist" })} className="flex items-center justify-center gap-2 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-2 text-sm font-semibold text-rose-600 disabled:opacity-50"><ShieldAlert className="size-4" />Blacklist</button>
                    <button disabled={submitting} onClick={() => openDecision(review, `Không thêm ${domain} vào blacklist`, { decision: "rejected", action: "none" })} className="flex items-center justify-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-600 disabled:opacity-50"><ShieldCheck className="size-4" />Bỏ qua</button>
                  </div>
                </div>
              </article>
            );
          })}
          {urlCases.length === 0 && <div className="rounded-2xl border border-dashed py-12 text-center text-muted-foreground">Không có URL đang chờ duyệt.</div>}
        </div>
      )}

      {!loading && !loadError && activeTab === "reports" && (
        <div className="space-y-4">
          {reports.map((report) => {
            const submitting = submittingIds.has(report.item_id);
            return (
              <article key={report.item_id} className="rounded-2xl border bg-card p-5">
                <div className="flex flex-col gap-6 md:flex-row">
                  <div className="min-w-0 flex-1 space-y-3">
                    <h2 className="flex items-center gap-2 text-sm font-bold"><FileText className="size-4 text-muted-foreground" /><span className="break-all">{report.analysis_id}</span></h2>
                    <p className="text-xs">Status: <strong>{report.status}</strong></p>
                    <div className="rounded-xl border p-3 bg-muted/30">
                      <h3 className="text-xs font-semibold uppercase text-muted-foreground">Chi tiết Report</h3>
                      <p className="mt-2 text-sm"><strong>Lý do:</strong> {report.reason}</p>
                      {report.comment && <p className="mt-1 text-sm text-muted-foreground"><strong>Ghi chú:</strong> {report.comment}</p>}
                    </div>
                    {report.analysis_content && (
                      <div className="rounded-xl border p-3 bg-muted/10">
                        <h3 className="text-xs font-semibold uppercase text-muted-foreground">Nội dung người dùng đã hỏi chat</h3>
                        <p className="mt-2 text-sm italic border-l-2 pl-3 py-1 border-muted-foreground text-muted-foreground">{report.analysis_content}</p>
                      </div>
                    )}
                    <div className="rounded-xl border p-3">
                      <h3 className="text-xs font-semibold uppercase text-muted-foreground">Evidence snapshot</h3>
                      {(report.evidence_snapshot ?? []).map((evidence, index) => <p key={`${evidence.type}:${index}`} className="mt-2 text-xs"><strong>{evidence.source}</strong>: {evidence.finding}</p>)}
                      {(report.evidence_snapshot?.length ?? 0) === 0 && <p className="mt-2 text-xs text-muted-foreground">Không có evidence.</p>}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-row gap-2 md:flex-col">
                    {report.status === "submitted" && (
                      <button disabled={submitting} onClick={() => startReportReview(report.item_id)} className="flex items-center justify-center gap-2 rounded-xl border border-blue-500/20 bg-blue-500/10 px-4 py-2 text-sm font-semibold text-blue-600 disabled:opacity-50">Start Review</button>
                    )}
                    {report.status === "reviewing" && (
                      <>
                        <button disabled={submitting} onClick={() => openReportDecision(report, `Approve Report`, { decision: "approved" })} className="flex items-center justify-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-600 disabled:opacity-50"><ShieldCheck className="size-4" />Approve</button>
                        <button disabled={submitting} onClick={() => openReportDecision(report, `Reject Report`, { decision: "rejected" })} className="flex items-center justify-center gap-2 rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-2 text-sm font-semibold text-rose-600 disabled:opacity-50"><ShieldAlert className="size-4" />Reject</button>
                        <button disabled={submitting} onClick={() => openReportDecision(report, `Dismiss Report`, { decision: "dismissed" })} className="flex items-center justify-center gap-2 rounded-xl border border-gray-500/20 bg-gray-500/10 px-4 py-2 text-sm font-semibold text-gray-600 disabled:opacity-50"><XCircle className="size-4" />Dismiss</button>
                      </>
                    )}
                  </div>
                </div>
              </article>
            );
          })}
          {reports.length === 0 && <div className="rounded-2xl border border-dashed py-12 text-center text-muted-foreground">Không có report.</div>}
        </div>
      )}

      {pending && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="decision-title">
          <div className="w-full max-w-md rounded-2xl border bg-card p-6 shadow-xl">
            <h2 id="decision-title" className="text-lg font-bold">{pending.title}</h2>
            <p className="mt-2 text-sm text-muted-foreground">Ghi chú là bắt buộc và sẽ được lưu vào audit trail.</p>
            <label htmlFor="review-note" className="mt-4 block text-sm font-medium">Ghi chú reviewer</label>
            <textarea id="review-note" autoFocus value={note} onChange={(event) => setNote(event.target.value)} className="mt-1 min-h-24 w-full rounded-lg border border-border bg-background p-3 text-sm" />
            <div className="mt-5 flex justify-end gap-3">
              <button type="button" onClick={() => setPending(null)} className="rounded-lg px-4 py-2 text-sm font-medium hover:bg-muted">Hủy</button>
              <button type="button" disabled={!note.trim() || submittingIds.has(pending.analysis.analysis_id)} onClick={() => void submitDecision()} className="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Xác nhận</button>
            </div>
          </div>
        </div>
      )}

      {pendingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="decision-title">
          <div className="w-full max-w-md rounded-2xl border bg-card p-6 shadow-xl">
            <h2 id="decision-title" className="text-lg font-bold">{pendingReport.title}</h2>
            <p className="mt-2 text-sm text-muted-foreground">Ghi chú là bắt buộc và sẽ được lưu vào audit trail.</p>
            <label htmlFor="review-note" className="mt-4 block text-sm font-medium">Ghi chú reviewer</label>
            <textarea id="review-note" autoFocus value={note} onChange={(event) => setNote(event.target.value)} className="mt-1 min-h-24 w-full rounded-lg border border-border bg-background p-3 text-sm" />
            <div className="mt-5 flex justify-end gap-3">
              <button type="button" onClick={() => setPendingReport(null)} className="rounded-lg px-4 py-2 text-sm font-medium hover:bg-muted">Hủy</button>
              <button type="button" disabled={!note.trim() || submittingIds.has(pendingReport.report.item_id)} onClick={() => void submitReportDecision()} className="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Xác nhận</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
