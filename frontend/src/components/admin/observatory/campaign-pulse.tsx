"use client";

import { useState, type FormEvent } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, FileClock, RotateCw, Search } from "lucide-react";

import type {
  SecurityCampaignAuditRecordV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityCampaignReviewerStatusV4,
} from "@/types/generated/api-v4";

export interface CampaignPulseQuery { q: string; status: SecurityCampaignReviewerStatusV4 | null; page: number }

export function CampaignPulse({ page, query, loading, error, detail, audit, detailLoading, detailError, onQueryChange, onRetry, onSelect }: {
  page: SecurityCampaignPageV4 | null;
  query: CampaignPulseQuery;
  loading: boolean;
  error: string | null;
  detail: SecurityCampaignRecordV4 | null;
  audit: SecurityCampaignAuditRecordV4[];
  detailLoading: boolean;
  detailError: string | null;
  onQueryChange(query: CampaignPulseQuery): void;
  onRetry(): void;
  onSelect(campaignId: string): void;
}) {
  const [draft, setDraft] = useState(query.q);
  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;
  const submit = (event: FormEvent) => { event.preventDefault(); onQueryChange({ ...query, q: draft.trim().slice(0, 200), page: 1 }); };
  return (
    <section aria-labelledby="campaign-pulse-heading" className="case-panel overflow-hidden">
      <header className="border-b border-border/70 p-5"><h2 id="campaign-pulse-heading" className="text-lg font-semibold">Chiến dịch</h2></header>
      <div className="grid lg:grid-cols-[minmax(20rem,0.85fr)_minmax(22rem,1.15fr)]">
        <div className="border-b border-border/70 p-5 lg:border-b-0 lg:border-r">
          <form onSubmit={submit} role="search" className="grid gap-2 sm:grid-cols-[1fr_11rem_auto]">
            <div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input aria-label="Tìm campaign hypothesis" value={draft} onChange={(event) => setDraft(event.target.value)} className="w-full rounded-xl border border-input bg-background py-2.5 pl-9 pr-3 text-xs" placeholder="Hypothesis…" /></div>
            <select aria-label="Lọc campaign status" value={query.status ?? ""} onChange={(event) => onQueryChange({ ...query, status: event.target.value ? event.target.value as SecurityCampaignReviewerStatusV4 : null, page: 1 })} className="rounded-xl border border-input bg-background px-3 py-2.5 text-xs"><option value="">All statuses</option><option value="pending_review">pending_review</option><option value="confirmed">confirmed</option><option value="rejected">rejected</option></select>
            <button className="rounded-xl bg-primary px-3 py-2.5 text-xs font-semibold text-primary-foreground">Tìm</button>
          </form>
          {loading && <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải campaigns…</p>}
          {error && !loading && <div role="alert" className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-800 dark:text-rose-200">{error}<button type="button" onClick={onRetry} className="ml-2 inline-flex items-center gap-1 font-bold underline"><RotateCw className="size-3.5" />Thử lại</button></div>}
          {!loading && !error && page && (page.items.length ? <ol className="mt-4 space-y-2">{page.items.map((item) => <li key={item.campaign_id}><button type="button" onClick={() => onSelect(item.campaign_id)} aria-pressed={detail?.campaign_id === item.campaign_id} className="w-full rounded-xl border border-border bg-background/55 p-3 text-left hover:border-primary/35 aria-pressed:border-primary aria-pressed:bg-primary/5"><span className="flex justify-between gap-3"><span className="text-xs font-semibold leading-5">{item.hypothesis}</span><span className="h-fit rounded-md bg-muted px-2 py-1 font-mono text-[9px]">{item.reviewer_status}</span></span><span className="mt-2 block text-[10px] text-muted-foreground">{item.analysis_ids.length} members · {Object.keys(item.aggregate_signals).length} named signals</span></button></li>)}</ol> : <p className="mt-4 rounded-xl border border-dashed border-border py-8 text-center text-sm text-muted-foreground">Không có campaign phù hợp.</p>)}
          {!loading && !error && page && page.total > 0 && <nav aria-label="Campaign pages" className="mt-4 flex justify-end gap-2"><button type="button" aria-label="Campaign page trước" disabled={query.page <= 1} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40"><ChevronLeft className="size-4" /></button><button type="button" aria-label="Campaign page sau" disabled={query.page >= totalPages} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40"><ChevronRight className="size-4" /></button></nav>}
        </div>

        <div className="p-5">
          {detailLoading && <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải campaign detail…</p>}
          {detailError && !detailLoading && <p role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-800 dark:text-rose-200">{detailError}</p>}
          {!detailLoading && !detailError && !detail && <div className="grid min-h-56 place-items-center text-center text-muted-foreground"><div><FileClock className="mx-auto size-6" /><p className="mt-2 text-sm">Chọn một chiến dịch để xem chi tiết.</p></div></div>}
          {!detailLoading && !detailError && detail && <div className="space-y-5"><div><h3 className="text-base font-semibold leading-6">{detail.hypothesis}</h3><p className="mt-2 text-[10px] text-muted-foreground"><time dateTime={detail.window_started_at}>{new Date(detail.window_started_at).toLocaleString("vi-VN")}</time> → <time dateTime={detail.window_ended_at}>{new Date(detail.window_ended_at).toLocaleString("vi-VN")}</time></p></div><dl className="grid grid-cols-2 gap-3 text-xs"><div className="rounded-xl bg-muted/55 p-3"><dt className="text-muted-foreground">Phân tích liên quan</dt><dd className="mt-1 text-xl font-bold">{detail.analysis_ids.length}</dd></div><div className="rounded-xl bg-muted/55 p-3"><dt className="text-muted-foreground">Bằng chứng</dt><dd className="mt-1 text-xl font-bold">{detail.evidence_refs.length}</dd></div></dl><div><h4 className="text-xs font-bold">Tín hiệu tổng hợp</h4><dl className="mt-2 space-y-1">{Object.entries(detail.aggregate_signals).map(([signal, count]) => <div key={signal} className="flex justify-between gap-3 rounded-lg border border-border px-3 py-2 text-[11px]"><dt className="break-all font-mono">{signal}</dt><dd className="font-bold">{count}</dd></div>)}</dl></div><details className="group border-t border-border/60 pt-3"><summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">Lịch sử duyệt và metadata<ChevronDown className="size-4 transition-transform group-open:rotate-180" /></summary><div className="mt-3"><h4 className="sr-only">Lịch sử duyệt</h4>{audit.length ? <ol className="space-y-2">{audit.map((event) => <li key={event.audit_id} className="border-l-2 border-primary/35 pl-3 text-[11px] leading-5"><p className="font-mono">{event.previous_status} → {event.status}</p><p>{event.note}</p><p className="text-muted-foreground">{event.reviewer_id} · <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString("vi-VN")}</time></p></li>)}</ol> : <p className="text-xs text-muted-foreground">Chưa có lịch sử duyệt.</p>}<p className="mt-3 font-mono text-[9px] text-muted-foreground">{detail.clustering_version} · {detail.campaign_id}</p></div></details></div>}
        </div>
      </div>
    </section>
  );
}
