"use client";

import { useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, RotateCw, Search } from "lucide-react";

import type { SecurityDomainIntelligencePageV4, SecurityRiskV4, PotentialThreatV4 } from "@/types/generated/api-v4";

export interface DomainExplorerQuery {
  q: string;
  risk: SecurityRiskV4 | null;
  threatType: PotentialThreatV4 | null;
  page: number;
}

const riskOptions: SecurityRiskV4[] = ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "SAFE", "INSUFFICIENT_EVIDENCE"];
const threatOptions: PotentialThreatV4[] = ["PHISHING", "BRAND_IMPERSONATION", "FINANCIAL_SCAM", "RECRUITMENT_SCAM", "PROMOTION_PRIZE_SCAM", "CREDENTIAL_THEFT", "UNDETERMINED_SECURITY_THREAT"];

function Distribution({ values }: { values: Record<string, number> }) {
  const entries = Object.entries(values).filter(([, count]) => count > 0);
  return entries.length ? <ul className="flex flex-wrap gap-1.5">{entries.map(([label, count]) => <li key={label} className="rounded-md border border-border bg-background px-2 py-1 font-mono text-[9px]">{label} · {count}</li>)}</ul> : <span className="text-muted-foreground">—</span>;
}

export function DomainExplorer({
  page,
  query,
  loading,
  error,
  onQueryChange,
  onRetry,
}: {
  page: SecurityDomainIntelligencePageV4 | null;
  query: DomainExplorerQuery;
  loading: boolean;
  error: string | null;
  onQueryChange(query: DomainExplorerQuery): void;
  onRetry(): void;
}) {
  const [draft, setDraft] = useState(query.q);
  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onQueryChange({ ...query, q: draft.trim().slice(0, 253), page: 1 });
  };

  return (
    <section aria-labelledby="domain-explorer-heading" className="case-panel overflow-hidden">
      <header className="border-b border-border/70 p-5">
        <p className="micro-label">DOMAIN INTELLIGENCE</p>
        <h2 id="domain-explorer-heading" className="mt-1 text-lg font-semibold">Ranked domain observations</h2>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">Counts, distributions và observation window do API aggregate trả về.</p>
      </header>
      <div className="p-5">
        <form onSubmit={submit} role="search" className="grid gap-2 md:grid-cols-[minmax(12rem,1fr)_11rem_13rem_auto]">
          <div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input aria-label="Tìm domain" value={draft} onChange={(event) => setDraft(event.target.value)} maxLength={253} placeholder="Domain…" className="w-full rounded-xl border border-input bg-background py-2.5 pl-9 pr-3 text-sm" /></div>
          <select aria-label="Lọc domain theo risk" value={query.risk ?? ""} onChange={(event) => onQueryChange({ ...query, risk: event.target.value ? event.target.value as SecurityRiskV4 : null, page: 1 })} className="rounded-xl border border-input bg-background px-3 py-2.5 text-xs"><option value="">All risks</option>{riskOptions.map((risk) => <option key={risk}>{risk}</option>)}</select>
          <select aria-label="Lọc domain theo threat" value={query.threatType ?? ""} onChange={(event) => onQueryChange({ ...query, threatType: event.target.value ? event.target.value as PotentialThreatV4 : null, page: 1 })} className="rounded-xl border border-input bg-background px-3 py-2.5 text-xs"><option value="">All threats</option>{threatOptions.map((threat) => <option key={threat}>{threat}</option>)}</select>
          <button type="submit" className="rounded-xl bg-primary px-4 py-2.5 text-xs font-semibold text-primary-foreground">Search</button>
        </form>

        {loading && <p role="status" className="py-12 text-center text-sm text-muted-foreground">Đang tải domain intelligence…</p>}
        {error && !loading && <div role="alert" className="my-4 rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-800 dark:text-rose-200">{error}<button type="button" onClick={onRetry} className="ml-2 inline-flex items-center gap-1 font-bold underline"><RotateCw className="size-3.5" />Thử lại</button></div>}
        {!loading && !error && page && (
          <>
            <div className="my-4 flex justify-between text-[11px] text-muted-foreground"><span>{page.total} domains</span><span>Page {query.page}/{totalPages}</span></div>
            {page.items.length ? (
              <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Domain intelligence table">
                <table className="w-full min-w-[760px] border-collapse text-left text-xs">
                  <thead><tr className="border-b border-border text-[10px] uppercase tracking-wide text-muted-foreground"><th className="pb-2 pr-4">Domain</th><th className="pb-2 pr-4">Counts</th><th className="pb-2 pr-4">Risk distribution</th><th className="pb-2 pr-4">Threat distribution</th><th className="pb-2">Observed</th></tr></thead>
                  <tbody>{page.items.map((item) => <tr key={item.domain} className="border-b border-border/60 align-top"><td className="py-3 pr-4"><p className="max-w-56 break-all font-mono font-semibold">{item.domain}</p><p className="mt-1 text-[10px] text-muted-foreground">{item.evidence_refs.length} evidence refs</p></td><td className="py-3 pr-4"><p><strong>{item.analysis_count}</strong> analyses</p><p className="mt-1"><strong>{item.report_count}</strong> reports</p></td><td className="py-3 pr-4"><Distribution values={item.risk_distribution} /></td><td className="py-3 pr-4"><Distribution values={item.threat_distribution} /></td><td className="py-3"><p><span className="text-muted-foreground">First</span> <time dateTime={item.first_seen_at}>{new Date(item.first_seen_at).toLocaleString("vi-VN")}</time></p><p className="mt-1"><span className="text-muted-foreground">Last</span> <time dateTime={item.last_seen_at}>{new Date(item.last_seen_at).toLocaleString("vi-VN")}</time></p></td></tr>)}</tbody>
                </table>
              </div>
            ) : <p className="rounded-xl border border-dashed border-border py-10 text-center text-sm text-muted-foreground">Không có domain phù hợp.</p>}
            {page.total > 0 && <nav aria-label="Domain pages" className="mt-4 flex justify-end gap-2"><button type="button" disabled={query.page <= 1} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40" aria-label="Domain page trước"><ChevronLeft className="size-4" /></button><button type="button" disabled={query.page >= totalPages} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border p-2 disabled:opacity-40" aria-label="Domain page sau"><ChevronRight className="size-4" /></button></nav>}
          </>
        )}
      </div>
    </section>
  );
}
