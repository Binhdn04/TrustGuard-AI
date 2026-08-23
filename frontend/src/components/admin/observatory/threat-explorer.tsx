"use client";

import { ChevronDown, ChevronLeft, ChevronRight, RotateCw } from "lucide-react";

import type { SecurityRiskV4, SecurityThreatIntelligencePageV4 } from "@/types/generated/api-v4";

export interface ThreatExplorerQuery { risk: SecurityRiskV4 | null; page: number }
const riskOptions: SecurityRiskV4[] = ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "SAFE", "INSUFFICIENT_EVIDENCE"];

export function ThreatExplorer({ page, query, loading, error, onQueryChange, onRetry }: {
  page: SecurityThreatIntelligencePageV4 | null;
  query: ThreatExplorerQuery;
  loading: boolean;
  error: string | null;
  onQueryChange(query: ThreatExplorerQuery): void;
  onRetry(): void;
}) {
  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;
  return (
    <section aria-labelledby="threat-explorer-heading" className="case-panel overflow-hidden">
      <header className="flex flex-col justify-between gap-3 border-b border-border/70 p-5 sm:flex-row sm:items-end">
        <h2 id="threat-explorer-heading" className="text-lg font-semibold">Nhóm nguy cơ</h2>
        <select aria-label="Lọc threat theo risk" value={query.risk ?? ""} onChange={(event) => onQueryChange({ risk: event.target.value ? event.target.value as SecurityRiskV4 : null, page: 1 })} className="rounded-xl border border-input bg-background px-3 py-2.5 text-xs"><option value="">All risks</option>{riskOptions.map((risk) => <option key={risk}>{risk}</option>)}</select>
      </header>
      <div className="p-5">
        {loading && <p role="status" className="py-12 text-center text-sm text-muted-foreground">Đang tải threat intelligence…</p>}
        {error && !loading && <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-800 dark:text-rose-200">{error}<button type="button" onClick={onRetry} className="ml-2 inline-flex items-center gap-1 font-bold underline"><RotateCw className="size-3.5" />Thử lại</button></div>}
        {!loading && !error && page && (page.items.length ? <ol className="space-y-3">{page.items.map((item, index) => <li key={item.threat_type} className="rounded-xl border border-border/75 bg-background/55 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-mono text-[10px] text-muted-foreground">#{String(page.offset + index + 1).padStart(2, "0")}</p><h3 className="mt-1 text-sm font-bold">{item.threat_type}</h3></div><p className="text-right text-xs"><strong className="text-base">{item.analysis_count}</strong> phân tích<br /><span className="text-muted-foreground">{item.report_count} báo cáo</span></p></div><details className="group mt-3 border-t border-border/60 pt-3"><summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">Chi tiết quan sát<ChevronDown className="size-4 transition-transform group-open:rotate-180" /></summary><dl className="mt-3 grid gap-3 text-[11px] sm:grid-cols-2"><div><dt className="text-muted-foreground">Phân bố rủi ro</dt><dd className="mt-1 flex flex-wrap gap-1">{Object.entries(item.risk_distribution).map(([risk, count]) => <span key={risk} className="rounded-md border border-border px-2 py-1 font-mono">{risk} · {count}</span>)}</dd></div><div><dt className="text-muted-foreground">Domain quan sát</dt><dd className="mt-1 break-all font-mono">{item.domains.length ? item.domains.join(" · ") : "—"}</dd></div></dl><p className="mt-3 text-[10px] text-muted-foreground"><time dateTime={item.first_seen_at}>{new Date(item.first_seen_at).toLocaleString("vi-VN")}</time> → <time dateTime={item.last_seen_at}>{new Date(item.last_seen_at).toLocaleString("vi-VN")}</time> · {item.evidence_refs.length} bằng chứng</p></details></li>)}</ol> : <p className="rounded-xl border border-dashed border-border py-10 text-center text-sm text-muted-foreground">Không có nhóm nguy cơ phù hợp.</p>)}
        {!loading && !error && page && page.total > 0 && <nav aria-label="Threat pages" className="mt-4 flex justify-end gap-2"><button type="button" aria-label="Threat page trước" disabled={query.page <= 1} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40"><ChevronLeft className="size-4" /></button><button type="button" aria-label="Threat page sau" disabled={query.page >= totalPages} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40"><ChevronRight className="size-4" /></button></nav>}
      </div>
    </section>
  );
}
