"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, Ban, CheckCircle, ClipboardList, Flag, ShieldAlert, XCircle } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { getAnalysisApi } from "@/lib/api/analysis-api";
import type {
  AdminDecisionAudit,
  AnalysisReportRecord,
  AnalysisResponse,
  BlacklistEntry,
} from "@/types/analysis";

export default function AdminReviewPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [cases, setCases] = useState<AnalysisResponse[]>([]);
  const [reports, setReports] = useState<AnalysisReportRecord[]>([]);
  const [decisions, setDecisions] = useState<AdminDecisionAudit[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([]);
  const [selectedCase, setSelectedCase] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [note, setNote] = useState("");
  const [addToBlacklist, setAddToBlacklist] = useState(false);

  const loadCases = useCallback(async () => {
    try {
      const api = getAnalysisApi();
      const [queue, reportItems, decisionItems, blacklistItems] = await Promise.all([
        api.listAdminCases(),
        api.listAdminReports(),
        api.listAdminDecisions(),
        api.listAdminBlacklist(),
      ]);
      setCases(queue);
      setReports(reportItems);
      setDecisions(decisionItems);
      setBlacklist(blacklistItems);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không tải được hàng đợi review.");
    }
  }, []);

  useEffect(() => {
    if (!isLoading && user?.role !== "security_admin") {
      router.push("/");
      return;
    }
    if (!isLoading && user?.role === "security_admin") {
      const timeout = window.setTimeout(() => void loadCases(), 0);
      return () => window.clearTimeout(timeout);
    }
  }, [user, isLoading, router, loadCases]);

  async function decide(decision: "approved" | "rejected"): Promise<void> {
    if (!selectedCase) return;
    const trimmedNote = note.trim();
    if (!trimmedNote) {
      setError("Admin note là bắt buộc trước khi đưa ra quyết định.");
      return;
    }
    setSubmitting(true);
    try {
      await getAnalysisApi().decideAdminCase(selectedCase.analysis_id, {
        decision,
        action:
          decision === "approved" && addToBlacklist && (selectedCase.normalized_urls?.length ?? 0) > 0
            ? "add_to_blacklist"
            : "none",
        note: trimmedNote,
      });
      setSelectedCase(null);
      setNote("");
      setAddToBlacklist(false);
      await loadCases();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không lưu được quyết định review.");
    } finally {
      setSubmitting(false);
    }
  }

  if (!user || user.role !== "security_admin") return null;

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Admin Review Queue</h1>
        <p className="mt-1 text-sm text-muted-foreground">Các analysis critical đang chờ Security Admin quyết định</p>
      </div>

      {error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</p>}

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="space-y-3 rounded-xl border border-border bg-card p-4">
          {cases.map((item) => (
            <button key={item.analysis_id} type="button" onClick={() => {
              setSelectedCase(item);
              setNote("");
              setAddToBlacklist((item.normalized_urls?.length ?? 0) > 0);
              setError(null);
            }} className="w-full rounded-xl border border-border bg-background p-4 text-left transition hover:border-primary/40">
              <div className="flex items-start justify-between gap-4">
                <span className="text-xs font-semibold uppercase text-muted-foreground">{item.analysis_id.slice(0, 8)}</span>
                <span className="flex items-center rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700"><AlertTriangle className="mr-1 size-3" />{item.risk_score}</span>
              </div>
              <p className="mt-2 line-clamp-2 text-sm font-medium">{item.summary}</p>
              <p className="mt-2 text-xs text-muted-foreground">{new Date(item.created_at).toLocaleString("vi-VN")}</p>
            </button>
          ))}
          {cases.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">Không có case đang chờ review.</p>}
        </section>

        <section className="rounded-xl border border-border bg-card p-6">
          {!selectedCase ? (
            <p className="py-10 text-center text-sm text-muted-foreground">Chọn một case để xem evidence và đưa ra quyết định.</p>
          ) : (
            <div className="space-y-6">
              <div className="flex items-center gap-2"><ShieldAlert className="size-5 text-amber-500" /><h2 className="font-semibold">Case {selectedCase.analysis_id.slice(0, 8)}</h2></div>
              <div><h3 className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Kết luận</h3><p className="text-sm leading-6">{selectedCase.summary}</p></div>
              <div><h3 className="mb-2 text-xs font-semibold uppercase text-muted-foreground">Evidence</h3><ul className="space-y-2">{(selectedCase.evidence ?? []).map((evidence, index) => <li key={`${evidence.source}-${index}`} className="rounded-lg bg-muted/50 p-3 text-sm"><strong>{evidence.title}</strong><p className="mt-1 text-muted-foreground">{evidence.finding}</p></li>)}</ul></div>
              <div>
                <label htmlFor="admin-note" className="text-xs font-semibold uppercase text-muted-foreground">Admin note</label>
                <textarea id="admin-note" value={note} onChange={(event) => setNote(event.target.value)} disabled={submitting} maxLength={1000} rows={4} required className="mt-2 w-full resize-y rounded-xl border border-border bg-background px-3 py-2 text-sm" placeholder="Ghi rõ lý do phê duyệt hoặc bác bỏ case…" />
              </div>
              {(selectedCase.normalized_urls?.length ?? 0) > 0 && (
                <label className="flex items-start gap-3 rounded-xl border border-border bg-muted/30 p-3 text-sm">
                  <input type="checkbox" checked={addToBlacklist} onChange={(event) => setAddToBlacklist(event.target.checked)} disabled={submitting} className="mt-0.5 size-4 accent-red-600" />
                  <span><strong>Thêm domain vào blacklist</strong><span className="mt-1 block text-xs text-muted-foreground">Chỉ áp dụng khi case được phê duyệt; backend sẽ lưu audit decision trước khi ghi blacklist.</span></span>
                </label>
              )}
              <div className="grid gap-3 sm:grid-cols-2">
                <button disabled={submitting || !note.trim()} type="button" onClick={() => void decide("approved")} className="flex items-center justify-center rounded-lg bg-red-600 px-4 py-2.5 text-sm font-medium text-white disabled:opacity-50"><CheckCircle className="mr-2 size-4" />{addToBlacklist ? "Duyệt & thêm blacklist" : "Phê duyệt case"}</button>
                <button disabled={submitting || !note.trim()} type="button" onClick={() => void decide("rejected")} className="flex items-center justify-center rounded-lg border border-border bg-secondary px-4 py-2.5 text-sm font-medium disabled:opacity-50"><XCircle className="mr-2 size-4" />Bác bỏ cảnh báo</button>
              </div>
            </div>
          )}
        </section>
      </div>

      <div className="grid gap-6 xl:grid-cols-3">
        <section className="rounded-xl border border-border bg-card p-4">
          <div className="mb-4 flex items-center gap-2">
            <Flag className="size-4 text-amber-600" />
            <h2 className="font-semibold">Báo cáo người dùng</h2>
            <span className="ml-auto text-xs text-muted-foreground">{reports.length}</span>
          </div>
          <div className="max-h-80 space-y-3 overflow-y-auto">
            {reports.map((report) => (
              <article key={report.report_id} className="rounded-lg border border-border p-3 text-sm">
                <p className="font-medium">{report.reason}</p>
                {report.comment && <p className="mt-1 text-muted-foreground">{report.comment}</p>}
                <p className="mt-2 text-xs text-muted-foreground">
                  Case {report.analysis_id.slice(0, 8)} · {new Date(report.created_at).toLocaleString("vi-VN")}
                </p>
              </article>
            ))}
            {reports.length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">Chưa có báo cáo.</p>}
          </div>
        </section>

        <section className="rounded-xl border border-border bg-card p-4">
          <div className="mb-4 flex items-center gap-2">
            <ClipboardList className="size-4 text-blue-600" />
            <h2 className="font-semibold">Lịch sử quyết định</h2>
            <span className="ml-auto text-xs text-muted-foreground">{decisions.length}</span>
          </div>
          <div className="max-h-80 space-y-3 overflow-y-auto">
            {decisions.map((decision) => (
              <article key={decision.decision_id} className="rounded-lg border border-border p-3 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <strong>{decision.decision === "approved" ? "Đã duyệt" : "Đã bác bỏ"}</strong>
                  <span className="text-xs text-muted-foreground">{decision.reviewer_id}</span>
                </div>
                <p className="mt-1 text-muted-foreground">{decision.note}</p>
                <p className="mt-2 text-xs text-muted-foreground">
                  {decision.analysis_id ? `Case ${decision.analysis_id.slice(0, 8)} · ` : ""}
                  {new Date(decision.decided_at).toLocaleString("vi-VN")}
                </p>
              </article>
            ))}
            {decisions.length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">Chưa có quyết định.</p>}
          </div>
        </section>

        <section className="rounded-xl border border-border bg-card p-4">
          <div className="mb-4 flex items-center gap-2">
            <Ban className="size-4 text-red-600" />
            <h2 className="font-semibold">Blacklist</h2>
            <span className="ml-auto text-xs text-muted-foreground">{blacklist.length}</span>
          </div>
          <div className="max-h-80 space-y-3 overflow-y-auto">
            {blacklist.map((entry) => (
              <article key={entry.domain} className="rounded-lg border border-border p-3 text-sm">
                <p className="break-all font-mono font-medium">{entry.domain}</p>
                <p className="mt-2 text-xs text-muted-foreground">
                  {new Date(entry.added_at).toLocaleString("vi-VN")}
                </p>
              </article>
            ))}
            {blacklist.length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">Blacklist đang trống.</p>}
          </div>
        </section>
      </div>
    </div>
  );
}
