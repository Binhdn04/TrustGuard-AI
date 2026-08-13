import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2, RefreshCw, ShieldCheck, XCircle } from "lucide-react";

import type { AnalysisApi } from "@/lib/api/analysis-api.types";
import { ApiError } from "@/lib/api/http-analysis-api";
import { cn } from "@/lib/utils";
import type {
  AdminActionAuditRecordV3,
  AdminActionRecordV3,
  AdminActionStatusV3,
  ReviewDecisionV3,
} from "@/types/generated/api-v3";

const PAGE_SIZE = 10;

function ActionStatus({ value }: { value: AdminActionStatusV3 }) {
  const successful = value === "executed";
  const failed = value === "failed";
  return <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase", successful ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" : failed || value === "rejected" ? "border-rose-500/25 bg-rose-500/10 text-rose-700 dark:text-rose-300" : "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300")}>{value.replaceAll("_", " ")}</span>;
}

export function ActionExecutionPanel({ api }: { api: AnalysisApi }) {
  const [status, setStatus] = useState<"all" | AdminActionStatusV3>("all");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<AdminActionRecordV3[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AdminActionRecordV3 | null>(null);
  const [audit, setAudit] = useState<AdminActionAuditRecordV3[]>([]);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<ReviewDecisionV3>("approved");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listAdminActions({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, ...(status !== "all" ? { status } : {}) });
      setItems(result.items);
      setTotal(result.total);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không thể tải reviewed actions.");
    } finally {
      setLoading(false);
    }
  }, [api, page, status]);

  useEffect(() => { void Promise.resolve().then(load); }, [load]);

  const select = async (actionId: string) => {
    setSelectedId(actionId);
    setDetail(null);
    setAudit([]);
    setDetailLoading(true);
    setError(null);
    try {
      const [record, records] = await Promise.all([api.getAdminAction(actionId), api.listAdminActionAudit(actionId)]);
      setDetail(record);
      setAudit(records);
      setDecision("approved");
      setNote("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không thể tải action detail/audit.");
    } finally {
      setDetailLoading(false);
    }
  };

  const submit = async () => {
    if (!detail || detail.status !== "pending_review" || !note.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.decideAdminAction(detail.action_id, { decision, note: note.trim() });
      await Promise.all([load(), select(detail.action_id)]);
    } catch (caught) {
      const message = caught instanceof ApiError && caught.status === 409
        ? "Action đã được reviewer khác xử lý. Queue và detail vừa được tải lại."
        : caught instanceof Error ? caught.message : "Không thể ghi action decision.";
      if (caught instanceof ApiError && caught.status === 409) {
        await Promise.all([load(), select(detail.action_id)]);
      }
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <section aria-labelledby="action-execution-heading" className="space-y-5">
      <header className="border-b border-border/70 pb-5"><p className="micro-label text-primary">V3 reviewed-action boundary</p><h2 id="action-execution-heading" className="mt-1 text-2xl font-bold">Action execution review</h2><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Approve/reject dùng contract v3 hiện có. Chỉ trạng thái <strong>executed</strong> được hiển thị là thành công; failed hoặc thiếu action sink luôn là lỗi.</p></header>
      <div className="grid gap-5 xl:grid-cols-[minmax(18rem,0.65fr)_minmax(25rem,1.35fr)]">
        <section className="overflow-hidden rounded-2xl border border-border bg-card">
          <div className="flex items-center justify-between gap-3 border-b border-border p-4"><div><p className="micro-label">Action queue</p><p className="mt-1 text-xs text-muted-foreground">{total} records</p></div><select aria-label="Lọc reviewed action theo trạng thái" value={status} onChange={(event) => { setStatus(event.target.value as typeof status); setPage(1); }} className="rounded-xl border border-border bg-background px-3 py-2 text-xs"><option value="all">all</option>{["pending_review", "approved", "rejected", "executed", "failed"].map((value) => <option key={value} value={value}>{value}</option>)}</select></div>
          {loading && <p role="status" className="p-4 text-sm text-muted-foreground"><Loader2 className="mr-2 inline size-4 animate-spin" />Đang tải actions…</p>}
          {!loading && <div className="divide-y divide-border">{items.map((item) => <button key={item.action_id} type="button" aria-pressed={selectedId === item.action_id} onClick={() => void select(item.action_id)} className={cn("w-full p-4 text-left hover:bg-muted/45", selectedId === item.action_id && "bg-primary/8")}><span className="flex flex-wrap items-center gap-2"><ActionStatus value={item.status} /><span className="font-mono text-[10px] text-muted-foreground">{new Date(item.proposed_at).toLocaleString("vi-VN")}</span></span><span className="mt-2 block text-sm font-semibold">{item.action.replaceAll("_", " ")}</span><span className="mt-1 block break-all text-xs text-muted-foreground">{item.target ?? "No target"}</span></button>)}{items.length === 0 && <p className="p-8 text-center text-sm text-muted-foreground">Không có reviewed action.</p>}</div>}
          <div className="flex items-center justify-end gap-2 border-t border-border p-3 text-xs"><button aria-label="Action page trước" disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{page}/{lastPage}<button aria-label="Action page sau" disabled={page >= lastPage} onClick={() => setPage(page + 1)} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
        </section>

        <section className="rounded-2xl border border-border bg-card p-5">
          {!selectedId && <div className="grid min-h-72 place-items-center text-center"><div><ShieldCheck className="mx-auto size-8 text-muted-foreground" /><p className="mt-3 text-sm text-muted-foreground">Chọn action để tải detail và immutable audit.</p></div></div>}
          {detailLoading && <p role="status" className="py-20 text-center text-sm text-muted-foreground"><Loader2 className="mr-2 inline size-4 animate-spin" />Đang tải detail…</p>}
          {error && <div role="alert" className="mb-4 rounded-xl border border-rose-500/25 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={() => void (selectedId ? select(selectedId) : load())} className="ml-2 inline-flex items-center gap-1 font-semibold underline"><RefreshCw className="size-3" />Tải lại</button></div>}
          {detail && !detailLoading && <div className="space-y-5">
            <div><span className="flex flex-wrap items-center gap-2"><ActionStatus value={detail.status} /><span className="micro-label">{detail.contract_version}</span></span><h3 className="mt-2 text-xl font-bold">{detail.action.replaceAll("_", " ")}</h3><p className="mt-1 break-all text-sm text-muted-foreground">Target: {detail.target ?? "—"}</p><p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">Action {detail.action_id} · Security analysis {detail.security_analysis_id ?? "—"} · Legacy analysis {detail.analysis_id ?? "—"}</p></div>
            {detail.status === "executed" && <p className="flex gap-2 rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 text-sm text-emerald-700 dark:text-emerald-300"><CheckCircle2 className="size-4 shrink-0" />Execution completed at {detail.executed_at ? new Date(detail.executed_at).toLocaleString("vi-VN") : "unknown time"}.</p>}
            {detail.status === "failed" && <p className="flex gap-2 rounded-xl border border-rose-500/25 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300"><AlertTriangle className="size-4 shrink-0" />Execution failed: {detail.execution_error ?? "No execution error detail returned."}</p>}
            {detail.status === "rejected" && <p className="flex gap-2 rounded-xl border border-rose-500/25 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300"><XCircle className="size-4 shrink-0" />Reviewer rejected this action. It was not executed.</p>}
            <div><p className="micro-label">Evidence snapshot</p><div className="mt-2 space-y-2">{detail.evidence_snapshot.map((item, index) => <article key={`${item.source}:${item.observed_at}:${index}`} className="rounded-xl border border-border bg-background/55 p-3"><p className="text-xs font-semibold">{item.title}</p><p className="mt-1 text-xs text-muted-foreground">{item.source}: {item.finding}</p>{item.url && <p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">{item.url}</p>}</article>)}{detail.evidence_snapshot.length === 0 && <p className="rounded-xl border border-dashed border-border p-3 text-xs text-muted-foreground">No evidence snapshot. Reviewer should not approve without an adequate basis.</p>}</div></div>
            {detail.status === "pending_review" && <div className="rounded-xl border border-border p-4"><label className="text-xs font-semibold" htmlFor="action-decision">Decision</label><select id="action-decision" value={decision} onChange={(event) => setDecision(event.target.value as ReviewDecisionV3)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="approved">approved</option><option value="rejected">rejected</option></select><label className="mt-3 block text-xs font-semibold" htmlFor="action-review-note">Reviewer note</label><textarea id="action-review-note" value={note} onChange={(event) => setNote(event.target.value)} className="mt-1 min-h-24 w-full rounded-xl border border-border bg-background p-3 text-sm" /><button type="button" disabled={!note.trim() || submitting} onClick={() => void submit()} className="mt-3 w-full rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-45">{submitting ? "Đang xử lý…" : "Submit action decision"}</button></div>}
            <div><p className="micro-label">Decision audit</p><div className="mt-2 space-y-2">{audit.map((entry) => <article key={entry.decision_id} className="rounded-xl border border-border p-3 text-xs"><div className="flex flex-wrap items-center gap-2"><ActionStatus value={entry.execution_status} /><strong>{entry.decision}</strong><time className="text-muted-foreground" dateTime={entry.decided_at}>{new Date(entry.decided_at).toLocaleString("vi-VN")}</time></div><p className="mt-1 text-muted-foreground">{entry.reviewer_id}: {entry.note}</p>{entry.execution_error && <p className="mt-1 text-rose-700 dark:text-rose-300">{entry.execution_error}</p>}<p className="mt-1 text-[10px] text-muted-foreground">Evidence snapshot: {entry.evidence_snapshot.length}</p></article>)}{audit.length === 0 && <p className="text-xs text-muted-foreground">No decision audit yet.</p>}</div></div>
          </div>}
        </section>
      </div>
    </section>
  );
}
