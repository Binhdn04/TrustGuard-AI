"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Filter, HelpCircle, Loader2, Search, ShieldAlert, ShieldCheck } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import { cn } from "@/lib/utils";
import type { SecurityRiskV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

type FilterType = "all" | SecurityRiskV4 | "OUT_OF_SCOPE" | "NEED_MORE_INFO";

function displayFor(item: SecurityScopeResponseV4) {
  if (item.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") return { label: "Ngoài phạm vi", icon: HelpCircle, color: "text-muted-foreground bg-muted/50 border-border" };
  if (item.scope_decision === "NEED_MORE_INFO") return { label: "Cần thêm thông tin", icon: HelpCircle, color: "text-amber-700 bg-amber-500/10 border-amber-500/20" };
  if (item.risk === "SAFE" || item.risk === "LOW_RISK") return { label: item.risk === "SAFE" ? "Chưa phát hiện rủi ro" : "Rủi ro thấp", icon: ShieldCheck, color: "text-emerald-700 bg-emerald-500/10 border-emerald-500/20" };
  if (item.risk === "HIGH_RISK" || item.risk === "MALICIOUS") return { label: item.risk === "MALICIOUS" ? "Nguy hiểm" : "Rủi ro cao", icon: ShieldAlert, color: "text-rose-700 bg-rose-500/10 border-rose-500/20" };
  return { label: item.risk === "SUSPICIOUS" ? "Đáng ngờ" : "Chưa đủ bằng chứng", icon: AlertTriangle, color: "text-amber-700 bg-amber-500/10 border-amber-500/20" };
}

function searchableSummary(item: SecurityScopeResponseV4): string {
  const context = item.security_context;
  return [context?.claimed_entity, context?.scenario, context?.requested_action, context?.potential_threat, ...(context?.urls ?? [])].filter(Boolean).join(" ");
}

export default function HistoryPage() {
  const [items, setItems] = useState<SecurityScopeResponseV4[]>([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<FilterType>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try { setItems(await getSecurityAnalysisApi().listAnalyses()); }
    catch (loadError) { setError(loadError instanceof Error ? loadError.message : "Không thể tải lịch sử Security Triage."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void Promise.resolve().then(load); }, [load]);
  const filtered = useMemo(() => items.filter((item) => {
    if (search && !searchableSummary(item).toLocaleLowerCase("vi").includes(search.toLocaleLowerCase("vi"))) return false;
    if (filter === "all") return true;
    if (filter === "OUT_OF_SCOPE") return item.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK";
    if (filter === "NEED_MORE_INFO") return item.scope_decision === "NEED_MORE_INFO";
    return item.risk === filter;
  }), [filter, items, search]);

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
      <header className="mb-8"><h1 className="text-3xl font-bold">Lịch sử Security Triage</h1><p className="mt-2 text-muted-foreground">Chỉ hiển thị structured security context của tài khoản hiện tại, không lưu lại nội dung chat riêng tư.</p></header>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row"><div className="relative flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input aria-label="Tìm kiếm lịch sử bảo mật" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Tìm theo thực thể, kịch bản hoặc URL…" className="w-full rounded-xl border border-border bg-background py-2.5 pl-9 pr-4 text-sm" /></div><div className="relative sm:w-56"><Filter className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><select aria-label="Lọc lịch sử bảo mật" value={filter} onChange={(event) => setFilter(event.target.value as FilterType)} className="w-full rounded-xl border border-border bg-background py-2.5 pl-9 pr-3 text-sm"><option value="all">Tất cả</option><option value="MALICIOUS">Nguy hiểm</option><option value="HIGH_RISK">Rủi ro cao</option><option value="SUSPICIOUS">Đáng ngờ</option><option value="LOW_RISK">Rủi ro thấp</option><option value="INSUFFICIENT_EVIDENCE">Chưa đủ bằng chứng</option><option value="NEED_MORE_INFO">Cần thêm thông tin</option><option value="OUT_OF_SCOPE">Ngoài phạm vi</option></select></div></div>
      {loading && <div role="status" className="flex justify-center py-16"><Loader2 className="size-7 animate-spin text-primary" /><span className="sr-only">Đang tải</span></div>}
      {error && <div role="alert" className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-5 text-sm text-rose-700">{error}<button type="button" onClick={() => void load()} className="ml-2 font-bold underline">Thử lại</button></div>}
      {!loading && !error && <div className="space-y-4">{filtered.map((item) => { const display = displayFor(item); const Icon = display.icon; return <article key={item.analysis_id} className="rounded-2xl border border-border bg-card p-5"><div className="flex flex-col justify-between gap-4 sm:flex-row"><div className="min-w-0"><p className="font-semibold">{item.security_context?.claimed_entity ?? item.security_context?.potential_threat?.replaceAll("_", " ") ?? "Security scope review"}</p><p className="mt-1 text-sm text-muted-foreground">{item.explanation ?? item.follow_up_question ?? item.boundary_message}</p><p className="mt-2 text-xs text-muted-foreground">{new Date(item.completed_at ?? item.created_at).toLocaleString("vi-VN")} · {item.evidence.length} bằng chứng · {item.status}</p>{item.security_context?.urls.map((url) => <p key={url} className="mt-1 break-all text-xs text-muted-foreground">URL: {url}</p>)}</div><span className={cn("inline-flex h-fit shrink-0 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold", display.color)}><Icon className="size-4" />{display.label}</span></div></article>; })}{filtered.length === 0 && <div className="rounded-2xl border border-dashed border-border py-12 text-center text-muted-foreground">Chưa có kết quả phù hợp.</div>}</div>}
    </div>
  );
}
