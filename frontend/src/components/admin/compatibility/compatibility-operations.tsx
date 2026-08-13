"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Boxes, LockKeyhole, RefreshCw } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { AnalysisApi } from "@/lib/api/analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import type { OperationsMetricsResponseV3, SourceDiscoveryRecordV3, SourcePolicyRecordV3 } from "@/types/generated/api-v3";

type TimeRange = "24h" | "7d" | "30d";

export function CompatibilityOperations({ api = getAnalysisApi() }: { api?: AnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [metrics, setMetrics] = useState<OperationsMetricsResponseV3 | null>(null);
  const [sources, setSources] = useState<SourcePolicyRecordV3[]>([]);
  const [discoveries, setDiscoveries] = useState<SourceDiscoveryRecordV3[]>([]);
  const [state, setState] = useState({ loading: false, error: null as string | null });
  const [publisher, setPublisher] = useState("");
  const [pattern, setPattern] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!isAdmin) return;
    const to = new Date();
    const hours = timeRange === "24h" ? 24 : timeRange === "7d" ? 168 : 720;
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000);
    setState({ loading: true, error: null });
    const results = await Promise.allSettled([
      api.getOperationsMetrics(from.toISOString(), to.toISOString()),
      api.listSourcePolicies(),
      api.listSourceDiscoveries(),
    ] as const);
    const failed: string[] = [];
    if (results[0].status === "fulfilled") setMetrics(results[0].value); else { setMetrics(null); failed.push("v3 metrics"); }
    if (results[1].status === "fulfilled") setSources(results[1].value); else { setSources([]); failed.push("source policies"); }
    if (results[2].status === "fulfilled") setDiscoveries(results[2].value); else { setDiscoveries([]); failed.push("source discoveries"); }
    setState({ loading: false, error: failed.length ? `Compatibility data unavailable: ${failed.join(", ")}.` : null });
  }, [api, isAdmin, timeRange]);
  useEffect(() => { void Promise.resolve().then(load); }, [load]);

  const createSource = async () => {
    if (!publisher.trim() || !pattern.trim() || busy) return;
    setBusy(true); setState((current) => ({ ...current, error: null }));
    try {
      await api.createSourcePolicy({ publisher: publisher.trim(), normalized_pattern: pattern.trim(), tier: "B", source_type: "reviewed_news", explicit_deny: false, trusted_claim_review: false, allowed_operations: ["search", "read", "compare"], policy_version: `compat-${Date.now()}`, effective_from: new Date().toISOString(), effective_to: null, default_freshness_seconds: 21600 });
      setPublisher(""); setPattern(""); await load();
    } catch (error) { setState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể tạo v3 source policy." })); }
    finally { setBusy(false); }
  };

  const decideDiscovery = async (record: SourceDiscoveryRecordV3, decision: "promote" | "demote" | "deny") => {
    if (busy) return; setBusy(true); setState((current) => ({ ...current, error: null }));
    try { await api.decideSourceDiscovery(record.domain, { decision, note: `Compatibility admin ${decision}` }); await load(); }
    catch (error) { setState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể cập nhật source discovery." })); }
    finally { setBusy(false); }
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Admin access required</h1><p className="mt-2 text-sm text-muted-foreground">Compatibility operations are isolated from Security v4.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về New case</Link></div>;

  const calls = metrics?.usage.reduce((sum, item) => sum + item.calls, 0) ?? 0;
  const cost = metrics?.usage.reduce((sum, item) => sum + item.estimated_cost_usd, 0) ?? 0;
  const p95 = metrics?.latency.length ? Math.max(...metrics.latency.map((item) => item.p95_ms ?? 0)) : 0;
  return <div className="space-y-6"><header className="border-b border-amber-500/25 pb-6"><p className="micro-label text-amber-700 dark:text-amber-300">COMPATIBILITY / V3 GENERAL ANALYSIS</p><div className="mt-2 flex items-start gap-3"><span className="grid size-11 place-items-center rounded-2xl bg-amber-500/10 text-amber-700 dark:text-amber-300"><Boxes className="size-5" /></span><div><h1 className="text-3xl font-bold tracking-[-0.025em]">Compatibility Operations</h1><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Legacy provider metrics and source discovery only. These values are not Security v4 intelligence, risk or trust capabilities.</p></div></div></header><div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-amber-500/25 bg-amber-500/8 p-4"><p className="flex items-start gap-2 text-sm"><AlertTriangle className="mt-0.5 size-4 shrink-0" />This surface remains for compatibility and rollback; it must not drive v4 verdicts.</p><div className="flex gap-2"><select aria-label="Khoảng thời gian compatibility metrics" value={timeRange} onChange={(event) => setTimeRange(event.target.value as TimeRange)} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="24h">24h</option><option value="7d">7d</option><option value="30d">30d</option></select><button type="button" disabled={state.loading} onClick={() => void load()} className="rounded-xl border border-border px-3 py-2"><RefreshCw className={state.loading ? "size-4 animate-spin" : "size-4"} /></button></div></div>{state.error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{state.error}</p>}<section aria-label="V3 compatibility metrics" className="grid gap-3 sm:grid-cols-3">{[["Provider calls", calls.toLocaleString("vi-VN")], ["Highest P95", `${Math.round(p95)} ms`], ["Estimated cost", `$${cost.toFixed(3)}`]].map(([label, value]) => <article key={label} className="rounded-2xl border border-border bg-card p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 text-2xl font-bold">{state.loading ? "—" : value}</p><p className="mt-1 text-[10px] font-bold uppercase text-amber-700 dark:text-amber-300">v3 compatibility</p></article>)}</section><section className="space-y-4"><div><p className="micro-label">V3 source registry</p><h2 className="mt-1 text-xl font-bold">General fact-check sources</h2></div><div className="grid gap-2 rounded-2xl border border-border bg-card p-4 sm:grid-cols-[1fr_1fr_auto]"><input aria-label="Compatibility publisher" value={publisher} onChange={(event) => setPublisher(event.target.value)} placeholder="Publisher" className="rounded-xl border border-border bg-background px-3 py-2 text-sm" /><input aria-label="Compatibility source pattern" value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder="*.news.example" className="rounded-xl border border-border bg-background px-3 py-2 text-sm" /><button type="button" disabled={busy || !publisher.trim() || !pattern.trim()} onClick={() => void createSource()} className="rounded-xl bg-amber-600 px-4 py-2 text-sm font-semibold text-white disabled:opacity-45">Add v3 policy</button></div><div className="grid gap-3 lg:grid-cols-2">{sources.map((record) => <article key={record.source_id} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold text-amber-700 dark:text-amber-300">Tier {record.tier}</span><strong>{record.publisher}</strong><code className="text-xs text-muted-foreground">{record.normalized_pattern}</code></div><p className="mt-2 text-xs text-muted-foreground">{record.policy_version} · reviewer {record.reviewer_id} · {record.allowed_operations.join(", ")}</p></article>)}{sources.length === 0 && !state.loading && <p className="text-sm text-muted-foreground">No v3 source policy.</p>}</div></section><section className="space-y-3"><div><p className="micro-label">V3 source discovery</p><h2 className="mt-1 text-xl font-bold">Observed domains</h2></div>{discoveries.map((record) => <article key={record.domain} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{record.status}</span><strong>{record.publisher}</strong><code className="text-xs text-muted-foreground">{record.domain}</code></div><p className="mt-2 text-xs text-muted-foreground">Search {record.search_count} · extract {record.extract_success_count} · curated comparisons {record.curated_comparison_count}</p><div className="mt-3 flex gap-2">{record.status !== "promoted" && <button disabled={busy} onClick={() => void decideDiscovery(record, "promote")} className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white">Promote</button>}{record.status === "promoted" && <button disabled={busy} onClick={() => void decideDiscovery(record, "demote")} className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white">Demote</button>}{record.status !== "denied" && <button disabled={busy} onClick={() => void decideDiscovery(record, "deny")} className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white">Deny</button>}</div></article>)}{discoveries.length === 0 && !state.loading && <p className="text-sm text-muted-foreground">No source discovery.</p>}</section></div>;
}
