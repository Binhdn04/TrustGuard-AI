"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  CircleDollarSign,
  Clock3,
  ExternalLink,
  GitBranch,
  Loader2,
  RefreshCw,
  Scale,
  ShieldCheck,
} from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import { cn } from "@/lib/utils";
import type {
  AdminActionRecordV3,
  AdminActionAuditRecordV3,
  AppealAdminRecordV3,
  AppealOutcomeV3,
  CampaignDetailV3,
  CampaignSummaryV3,
  OperationsMetricsResponseV3,
  ReviewDecisionV3,
  SourcePolicyRecordV3,
  SourceDiscoveryRecordV3,
} from "@/types/generated/api-v3";
import type { BrandRecordV4, WhitelistRecordV4 } from "@/types/generated/api-v4";

type Tab = "appeals" | "actions" | "trust" | "campaigns" | "sources";
type TimeRange = "24h" | "7d" | "30d";
type DecisionTarget =
  | { kind: "appeal"; id: string; title: string }
  | { kind: "action"; id: string; title: string }
  | { kind: "campaign"; id: string; title: string };

const statusStyle: Record<string, string> = {
  submitted: "border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  under_review: "border-blue-500/20 bg-blue-500/10 text-blue-700 dark:text-blue-300",
  resolved: "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  pending_review: "border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  approved: "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  executed: "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  rejected: "border-rose-500/20 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  failed: "border-rose-500/20 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  confirmed: "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  observing: "border-blue-500/20 bg-blue-500/10 text-blue-700 dark:text-blue-300",
  promoted: "border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  demoted: "border-amber-500/20 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  denied: "border-rose-500/20 bg-rose-500/10 text-rose-700 dark:text-rose-300",
};

function StatusBadge({ value }: { value: string }) {
  return (
    <span className={cn("inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold", statusStyle[value] ?? "border-border bg-muted text-muted-foreground")}>
      {value.replaceAll("_", " ")}
    </span>
  );
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "short" }).format(new Date(value));
}

export function PlatformOperations() {
  const [activeTab, setActiveTab] = useState<Tab>("appeals");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [campaignFilter, setCampaignFilter] = useState<"all" | CampaignSummaryV3["reviewer_status"]>("all");
  const [metrics, setMetrics] = useState<OperationsMetricsResponseV3 | null>(null);
  const [appeals, setAppeals] = useState<AppealAdminRecordV3[]>([]);
  const [actions, setActions] = useState<AdminActionRecordV3[]>([]);
  const [brands, setBrands] = useState<BrandRecordV4[]>([]);
  const [whitelist, setWhitelist] = useState<WhitelistRecordV4[]>([]);
  const [actionAudits, setActionAudits] = useState<Record<string, AdminActionAuditRecordV3[]>>({});
  const [expandedAction, setExpandedAction] = useState<string | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignSummaryV3[]>([]);
  const [sources, setSources] = useState<SourcePolicyRecordV3[]>([]);
  const [sourceDiscoveries, setSourceDiscoveries] = useState<SourceDiscoveryRecordV3[]>([]);
  const [campaignDetails, setCampaignDetails] = useState<Record<string, CampaignDetailV3>>({});
  const [expandedCampaign, setExpandedCampaign] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dataWarnings, setDataWarnings] = useState<string[]>([]);
  const [decision, setDecision] = useState<DecisionTarget | null>(null);
  const [decisionValue, setDecisionValue] = useState<AppealOutcomeV3 | ReviewDecisionV3 | "confirmed">("uphold");
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    const to = new Date();
    const hours = timeRange === "24h" ? 24 : timeRange === "7d" ? 24 * 7 : 24 * 30;
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000);
    const api = getAnalysisApi();
    const securityApi = getSecurityAnalysisApi();
    const results = await Promise.allSettled([
        api.getOperationsMetrics(from.toISOString(), to.toISOString()),
        api.listAdminAppeals({ limit: 100 }),
        api.listAdminActions({ limit: 100 }),
        api.listCampaigns({ limit: 100 }),
        api.listSourcePolicies(),
        api.listSourceDiscoveries(),
        securityApi.listBrands(),
        securityApi.listWhitelist(),
    ] as const);
    const warnings: string[] = [];
    const [metricsResult, appealsResult, actionsResult, campaignsResult, sourcesResult, discoveriesResult, brandsResult, whitelistResult] = results;
    if (metricsResult.status === "fulfilled") setMetrics(metricsResult.value);
    else { setMetrics(null); warnings.push("metrics"); }
    if (appealsResult.status === "fulfilled") setAppeals(appealsResult.value.items);
    else { setAppeals([]); warnings.push("appeals"); }
    if (actionsResult.status === "fulfilled") setActions(actionsResult.value.items);
    else { setActions([]); warnings.push("reviewed actions"); }
    if (campaignsResult.status === "fulfilled") setCampaigns(campaignsResult.value.items);
    else { setCampaigns([]); warnings.push("campaigns"); }
    if (sourcesResult.status === "fulfilled") setSources(sourcesResult.value);
    else { setSources([]); warnings.push("source registry"); }
    if (discoveriesResult.status === "fulfilled") setSourceDiscoveries(discoveriesResult.value);
    else { setSourceDiscoveries([]); warnings.push("source discovery"); }
    if (brandsResult.status === "fulfilled") setBrands(brandsResult.value);
    else { setBrands([]); warnings.push("brand registry"); }
    if (whitelistResult.status === "fulfilled") setWhitelist(whitelistResult.value);
    else { setWhitelist([]); warnings.push("security whitelist"); }
    setDataWarnings(warnings);
    setLoading(false);
  }, [timeRange]);

  useEffect(() => {
    void Promise.resolve().then(load);
  }, [load]);

  const totals = useMemo(() => ({
    calls: metrics?.usage.reduce((sum, item) => sum + item.calls, 0) ?? 0,
    cost: metrics?.usage.reduce((sum, item) => sum + item.estimated_cost_usd, 0) ?? 0,
    p95: metrics?.latency.length
      ? Math.max(...metrics.latency.map((item) => item.p95_ms ?? 0))
      : 0,
    pending: appeals.filter((item) => item.status !== "resolved").length
      + actions.filter((item) => item.status === "pending_review").length,
  }), [actions, appeals, metrics]);

  const filteredCampaigns = useMemo(
    () => campaigns.filter((item) => campaignFilter === "all" || item.reviewer_status === campaignFilter),
    [campaignFilter, campaigns],
  );

  const openDecision = (target: DecisionTarget) => {
    setDecision(target);
    setDecisionValue(target.kind === "appeal" ? "uphold" : target.kind === "campaign" ? "confirmed" : "approved");
    setNote("");
  };

  const submitDecision = async () => {
    if (!decision || !note.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const api = getAnalysisApi();
      if (decision.kind === "appeal") {
        await api.decideAppeal(decision.id, {
          outcome: decisionValue as AppealOutcomeV3,
          note: note.trim(),
        });
      } else if (decision.kind === "action") {
        await api.decideAdminAction(decision.id, {
          decision: decisionValue as ReviewDecisionV3,
          note: note.trim(),
        });
      } else {
        await api.reviewCampaign(decision.id, {
          decision: decisionValue as "confirmed" | "rejected",
          note: note.trim(),
        });
      }
      setDecision(null);
      await load();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Không thể lưu quyết định.");
    } finally {
      setSubmitting(false);
    }
  };

  const toggleCampaign = async (campaignId: string) => {
    if (expandedCampaign === campaignId) {
      setExpandedCampaign(null);
      return;
    }
    setExpandedCampaign(campaignId);
    if (campaignDetails[campaignId]) return;
    try {
      const detail = await getAnalysisApi().getCampaign(campaignId);
      setCampaignDetails((current) => ({ ...current, [campaignId]: detail }));
    } catch (detailError) {
      setError(detailError instanceof Error ? detailError.message : "Không thể tải chi tiết chiến dịch.");
    }
  };

  const toggleActionAudit = async (actionId: string) => {
    if (expandedAction === actionId) {
      setExpandedAction(null);
      return;
    }
    setExpandedAction(actionId);
    if (actionAudits[actionId]) return;
    try {
      const audit = await getAnalysisApi().listAdminActionAudit(actionId);
      setActionAudits((current) => ({ ...current, [actionId]: audit }));
    } catch (auditError) {
      setError(auditError instanceof Error ? auditError.message : "Không thể tải audit trail.");
    }
  };

  return (
    <div className="space-y-8">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-primary"><Activity className="size-4" />Platform Wave 2</div>
          <h1 className="text-3xl font-bold tracking-tight">Trung tâm vận hành</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">Theo dõi chất lượng agent, chiến dịch rủi ro và các quyết định cần con người phê duyệt.</p>
        </div>
        <div className="flex gap-2">
          <select aria-label="Khoảng thời gian metrics" value={timeRange} onChange={(event) => { setLoading(true); setTimeRange(event.target.value as TimeRange); }} className="rounded-xl border border-border bg-background px-3 py-2.5 text-sm font-semibold"><option value="24h">24 giờ</option><option value="7d">7 ngày</option><option value="30d">30 ngày</option></select>
          <button type="button" onClick={() => { setLoading(true); setError(null); void load(); }} disabled={loading} className="inline-flex items-center justify-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-semibold hover:bg-muted disabled:opacity-50">
            <RefreshCw className={cn("size-4", loading && "animate-spin")} />Làm mới
          </button>
        </div>
      </header>

      {error && <div role="alert" className="flex items-start gap-2 rounded-xl border border-rose-500/20 bg-rose-500/10 p-4 text-sm text-rose-700 dark:text-rose-300"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{error}</div>}
      {dataWarnings.length > 0 && <div role="status" className="flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-800 dark:text-amber-200"><AlertTriangle className="mt-0.5 size-4 shrink-0" /><span>Một phần dữ liệu tạm thời không khả dụng: {dataWarnings.join(", ")}. Các phần tải thành công vẫn được giữ lại.</span></div>}

      <section aria-label="Chỉ số 24 giờ" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Yêu cầu provider", value: totals.calls.toLocaleString("vi-VN"), icon: BarChart3, hint: timeRange === "24h" ? "Trong 24 giờ" : timeRange === "7d" ? "Trong 7 ngày" : "Trong 30 ngày" },
          { label: "P95 cao nhất", value: `${Math.round(totals.p95)} ms`, icon: Clock3, hint: `${metrics?.latency.length ?? 0} operation` },
          { label: "Chi phí ước tính", value: `$${totals.cost.toFixed(3)}`, icon: CircleDollarSign, hint: "Theo usage ledger" },
          { label: "Chờ quyết định", value: totals.pending.toString(), icon: Scale, hint: "Appeals + actions" },
        ].map(({ label, value, icon: Icon, hint }) => (
          <article key={label} className="rounded-2xl border border-border bg-card p-5 shadow-sm">
            <div className="flex items-center justify-between"><p className="text-sm text-muted-foreground">{label}</p><Icon className="size-4 text-primary" /></div>
            <p className="mt-3 text-2xl font-bold">{loading ? "—" : value}</p>
            <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
          </article>
        ))}
      </section>

      {metrics && (
        <section className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
          <div className="rounded-2xl border border-border bg-card p-5">
            <h2 className="font-semibold">Phân bố mức rủi ro</h2>
            <div className="mt-5 space-y-3">
              {metrics.risk_distribution.map((item) => {
                const total = metrics.risk_distribution.reduce((sum, entry) => sum + entry.count, 0);
                const width = total ? (item.count / total) * 100 : 0;
                return <div key={item.risk_level} className="grid grid-cols-[72px_1fr_40px] items-center gap-3 text-xs"><span className="capitalize text-muted-foreground">{item.risk_level}</span><div className="h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${width}%` }} /></div><span className="text-right font-semibold">{item.count}</span></div>;
              })}
              {metrics.risk_distribution.length === 0 && <p className="text-sm text-muted-foreground">Chưa có dữ liệu trong cửa sổ này.</p>}
            </div>
          </div>
          <div className="rounded-2xl border border-border bg-card p-5">
            <h2 className="font-semibold">Tín hiệu phản hồi</h2>
            <dl className="mt-4 grid grid-cols-2 gap-4 text-sm">
              <div><dt className="text-muted-foreground">Reports</dt><dd className="mt-1 text-xl font-bold">{metrics.feedback.reports}</dd></div>
              <div><dt className="text-muted-foreground">Appeals</dt><dd className="mt-1 text-xl font-bold">{metrics.feedback.appeals}</dd></div>
              <div><dt className="text-muted-foreground">Overturned</dt><dd className="mt-1 text-xl font-bold">{metrics.feedback.appeals_overturned}</dd></div>
              <div><dt className="text-muted-foreground">False positive</dt><dd className="mt-1 text-xl font-bold">{metrics.feedback.false_positive_rate === null ? "—" : `${(metrics.feedback.false_positive_rate * 100).toFixed(1)}%`}</dd></div>
            </dl>
          </div>
          </div>
          <OperationsBreakdown metrics={metrics} />
        </section>
      )}
      {!loading && !metrics && <EmptyState icon={BarChart3} text="Không có dữ liệu operations cho khoảng thời gian đã chọn." />}

      <section>
        <div className="mb-5 flex max-w-2xl gap-1 rounded-xl bg-muted p-1" role="tablist">
          {([
            ["appeals", `Khiếu nại (${appeals.length})`],
            ["actions", `Hành động (${actions.length})`],
            ["trust", `Trust (${brands.length + whitelist.length})`],
            ["campaigns", `Chiến dịch (${campaigns.length})`],
            ["sources", `Nguồn (${sources.length})`],
          ] as Array<[Tab, string]>).map(([tab, label]) => (
            <button key={tab} type="button" role="tab" aria-selected={activeTab === tab} onClick={() => setActiveTab(tab)} className={cn("flex-1 rounded-lg px-3 py-2 text-sm font-semibold", activeTab === tab ? "bg-background shadow-sm" : "text-muted-foreground")}>{label}</button>
          ))}
        </div>

        {loading && <div aria-live="polite" className="grid place-items-center py-20"><Loader2 className="size-7 animate-spin text-primary" /></div>}

        {!loading && activeTab === "appeals" && <AppealList items={appeals} onDecide={(item) => openDecision({ kind: "appeal", id: item.appeal_id, title: `Xử lý khiếu nại ${item.appeal_id.slice(0, 8)}` })} />}
        {!loading && activeTab === "actions" && <ActionList items={actions} audits={actionAudits} expanded={expandedAction} onToggleAudit={(id) => void toggleActionAudit(id)} onDecide={(item) => openDecision({ kind: "action", id: item.action_id, title: `Phê duyệt ${item.action.replaceAll("_", " ")}` })} />}
        {!loading && activeTab === "trust" && <TrustRegistryList brands={brands} whitelist={whitelist} />}
        {!loading && activeTab === "campaigns" && <><div className="mb-4 flex justify-end"><select aria-label="Lọc campaign theo reviewer state" value={campaignFilter} onChange={(event) => setCampaignFilter(event.target.value as typeof campaignFilter)} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">Tất cả reviewer state</option><option value="pending_review">Pending review</option><option value="confirmed">Confirmed</option><option value="rejected">Rejected</option></select></div><CampaignList items={filteredCampaigns} details={campaignDetails} expanded={expandedCampaign} onToggle={(id) => void toggleCampaign(id)} onDecide={(item) => openDecision({ kind: "campaign", id: item.campaign_id, title: `Review campaign ${item.campaign_id.slice(0, 8)}` })} /></>}
        {!loading && activeTab === "sources" && <SourceRegistryList items={sources} discoveries={sourceDiscoveries} onCreated={load} />}
      </section>

      {decision && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="wave2-decision-title">
          <div className="w-full max-w-lg rounded-2xl border border-border bg-card p-6 shadow-2xl">
            <h2 id="wave2-decision-title" className="text-lg font-bold">{decision.title}</h2>
            <p className="mt-1 text-sm text-muted-foreground">Quyết định và ghi chú sẽ được lưu vào audit trail.</p>
            <label htmlFor="decision-value" className="mt-5 block text-sm font-medium">Quyết định</label>
            <select id="decision-value" value={decisionValue} onChange={(event) => setDecisionValue(event.target.value as AppealOutcomeV3 | ReviewDecisionV3 | "confirmed")} className="mt-1.5 w-full rounded-xl border border-border bg-background px-3 py-2.5 text-sm">
              {decision.kind === "appeal" ? <><option value="uphold">Giữ nguyên kết quả</option><option value="overturn">Đảo ngược kết quả</option><option value="inconclusive">Chưa đủ bằng chứng</option></> : decision.kind === "campaign" ? <><option value="confirmed">Xác nhận campaign</option><option value="rejected">Từ chối</option></> : <><option value="approved">Phê duyệt</option><option value="rejected">Từ chối</option></>}
            </select>
            <label htmlFor="decision-note" className="mt-4 block text-sm font-medium">Ghi chú reviewer</label>
            <textarea id="decision-note" autoFocus maxLength={5000} value={note} onChange={(event) => setNote(event.target.value)} className="mt-1.5 min-h-28 w-full rounded-xl border border-border bg-background p-3 text-sm" />
            <div className="mt-5 flex justify-end gap-3">
              <button type="button" onClick={() => setDecision(null)} className="rounded-xl px-4 py-2.5 text-sm font-semibold hover:bg-muted">Hủy</button>
              <button type="button" onClick={() => void submitDecision()} disabled={!note.trim() || submitting} className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50">{submitting && <Loader2 className="size-4 animate-spin" />}Lưu quyết định</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function OperationsBreakdown({ metrics }: { metrics: OperationsMetricsResponseV3 }) {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <section className="overflow-hidden rounded-2xl border border-border bg-card">
        <div className="border-b border-border p-5"><h2 className="font-semibold">Latency theo operation</h2><p className="mt-1 text-xs text-muted-foreground">Phân vị từ usage ledger trong khoảng đã chọn.</p></div>
        {metrics.latency.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-muted/40 text-xs text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Operation</th><th className="px-3 py-3 font-medium">Calls</th><th className="px-3 py-3 font-medium">P50</th><th className="px-3 py-3 font-medium">P95</th><th className="px-5 py-3 font-medium">P99</th></tr></thead><tbody>{metrics.latency.map((item) => <tr key={item.operation} className="border-t border-border"><td className="px-5 py-3 font-medium">{item.operation}</td><td className="px-3 py-3">{item.count}</td><td className="px-3 py-3">{item.p50_ms === null ? "—" : `${Math.round(item.p50_ms)} ms`}</td><td className="px-3 py-3">{item.p95_ms === null ? "—" : `${Math.round(item.p95_ms)} ms`}</td><td className="px-5 py-3">{item.p99_ms === null ? "—" : `${Math.round(item.p99_ms)} ms`}</td></tr>)}</tbody></table></div> : <p className="p-5 text-sm text-muted-foreground">Chưa có latency data.</p>}
      </section>

      <section className="overflow-hidden rounded-2xl border border-border bg-card">
        <div className="border-b border-border p-5"><h2 className="font-semibold">Cache theo provider</h2><p className="mt-1 text-xs text-muted-foreground">Hit/miss được tổng hợp, không chứa target hoặc nội dung riêng tư.</p></div>
        {metrics.cache.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-muted/40 text-xs text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Provider</th><th className="px-3 py-3 font-medium">Hits</th><th className="px-3 py-3 font-medium">Misses</th><th className="px-5 py-3 font-medium">Hit rate</th></tr></thead><tbody>{metrics.cache.map((item) => <tr key={item.provider} className="border-t border-border"><td className="px-5 py-3 font-medium">{item.provider}</td><td className="px-3 py-3">{item.hits}</td><td className="px-3 py-3">{item.misses}</td><td className="px-5 py-3">{item.hit_rate === null ? "—" : `${(item.hit_rate * 100).toFixed(1)}%`}</td></tr>)}</tbody></table></div> : <p className="p-5 text-sm text-muted-foreground">Chưa có cache data.</p>}
      </section>

      <section className="overflow-hidden rounded-2xl border border-border bg-card xl:col-span-2">
        <div className="border-b border-border p-5"><h2 className="font-semibold">Provider usage, quota và lỗi vận hành</h2><p className="mt-1 text-xs text-muted-foreground">Chi phí là ước tính; 429 và timeout được ghi riêng để phát hiện pressure.</p></div>
        {metrics.usage.length ? <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-muted/40 text-xs text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Provider / model</th><th className="px-3 py-3 font-medium">Calls</th><th className="px-3 py-3 font-medium">Tokens</th><th className="px-3 py-3 font-medium">Cost</th><th className="px-3 py-3 font-medium">Quota</th><th className="px-3 py-3 font-medium">429</th><th className="px-5 py-3 font-medium">Timeout</th></tr></thead><tbody>{metrics.usage.map((item) => <tr key={`${item.provider}:${item.model ?? "none"}`} className="border-t border-border"><td className="px-5 py-3"><p className="font-medium">{item.provider}</p><p className="text-xs text-muted-foreground">{item.model ?? "—"}</p></td><td className="px-3 py-3">{item.calls}</td><td className="px-3 py-3">{item.tokens.toLocaleString("vi-VN")}</td><td className="px-3 py-3">${item.estimated_cost_usd.toFixed(4)}</td><td className="px-3 py-3">{item.quota_used === null ? "—" : item.quota_used <= 1 ? `${(item.quota_used * 100).toFixed(1)}%` : item.quota_used.toFixed(1)}</td><td className={cn("px-3 py-3 font-semibold", item.rate_limited > 0 && "text-amber-600")}>{item.rate_limited}</td><td className={cn("px-5 py-3 font-semibold", item.timed_out > 0 && "text-rose-600")}>{item.timed_out}</td></tr>)}</tbody></table></div> : <p className="p-5 text-sm text-muted-foreground">Chưa có provider usage data.</p>}
      </section>
    </div>
  );
}

function AppealList({ items, onDecide }: { items: AppealAdminRecordV3[]; onDecide: (item: AppealAdminRecordV3) => void }) {
  if (!items.length) return <EmptyState icon={Scale} text="Không có khiếu nại trong hàng đợi." />;
  return <div className="space-y-4">{items.map((item) => <article key={item.appeal_id} className="rounded-2xl border border-border bg-card p-5"><div className="flex flex-col justify-between gap-5 md:flex-row"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={item.status} /><span className="text-xs text-muted-foreground">{formatDate(item.created_at)}</span></div><h2 className="mt-3 font-semibold">{item.reason}</h2>{item.comment && <p className="mt-2 text-sm text-muted-foreground">{item.comment}</p>}<p className="mt-3 font-mono text-xs text-muted-foreground">Analysis: {item.analysis_id} · Owner: {item.owner_id}</p>{item.status === "resolved" && <div className="mt-4 rounded-xl bg-muted/50 p-3 text-sm"><strong>{item.outcome}</strong><p className="mt-1 text-muted-foreground">{item.resolution_note}</p></div>}</div>{item.status !== "resolved" && <button type="button" onClick={() => onDecide(item)} className="inline-flex h-fit shrink-0 items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground"><Scale className="size-4" />Xử lý</button>}</div></article>)}</div>;
}

function ActionList({ items, audits, expanded, onToggleAudit, onDecide }: { items: AdminActionRecordV3[]; audits: Record<string, AdminActionAuditRecordV3[]>; expanded: string | null; onToggleAudit: (id: string) => void; onDecide: (item: AdminActionRecordV3) => void }) {
  if (!items.length) return <EmptyState icon={ShieldCheck} text="Không có hành động được đề xuất." />;
  return <div className="space-y-4">{items.map((item) => { const isOpen = expanded === item.action_id; const audit = audits[item.action_id]; return <article key={item.action_id} className="rounded-2xl border border-border bg-card p-5"><div className="flex flex-col justify-between gap-5 md:flex-row"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={item.status} /><span className="text-xs text-muted-foreground">{formatDate(item.proposed_at)}</span></div><h2 className="mt-3 font-semibold capitalize">{item.action.replaceAll("_", " ")}</h2>{item.target && <p className="mt-1 break-all text-sm text-muted-foreground">Target: {item.target}</p>}<p className="mt-2 font-mono text-xs text-muted-foreground">{item.security_analysis_id ? `Security analysis: ${item.security_analysis_id}` : item.analysis_id ? `Legacy analysis: ${item.analysis_id}` : "Không gắn analysis"}</p><p className="mt-3 text-xs text-muted-foreground">Evidence snapshot: {item.evidence_snapshot.length} mục</p>{item.review_note && <p className="mt-3 rounded-xl bg-muted/50 p-3 text-sm text-muted-foreground">{item.review_note}</p>}{item.execution_error && <p role="alert" className="mt-3 rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">Execution: {item.execution_error}</p>}<button type="button" aria-expanded={isOpen} onClick={() => onToggleAudit(item.action_id)} className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary">Audit trail <ChevronDown className={cn("size-4 transition-transform", isOpen && "rotate-180")} /></button>{isOpen && <div className="mt-3 space-y-2 rounded-xl border border-border bg-muted/20 p-3">{audit ? audit.map((entry) => <div key={entry.decision_id} className="text-xs"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={entry.execution_status} /><strong>{entry.decision}</strong><span className="text-muted-foreground">{formatDate(entry.decided_at)} · {entry.reviewer_id}</span></div><p className="mt-1 text-muted-foreground">{entry.note}</p><p className="mt-1 text-muted-foreground">Evidence snapshot: {entry.evidence_snapshot.length} mục</p></div>) : <span className="text-xs text-muted-foreground">Đang tải audit…</span>}{audit?.length === 0 && <span className="text-xs text-muted-foreground">Chưa có quyết định.</span>}</div>}</div>{item.status === "pending_review" && <button type="button" onClick={() => onDecide(item)} className="inline-flex h-fit shrink-0 items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground"><CheckCircle2 className="size-4" />Review</button>}</div></article>; })}</div>;
}

function TrustRegistryList({ brands, whitelist }: { brands: BrandRecordV4[]; whitelist: WhitelistRecordV4[] }) {
  return <div className="grid gap-6 xl:grid-cols-2"><section className="space-y-3"><div><h2 className="font-semibold">Brand registry</h2><p className="text-xs text-muted-foreground">Domain/contact chính thức có provenance và reviewer.</p></div>{brands.map((item) => <article key={item.brand_id} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={item.lifecycle} /><strong>{item.name}</strong><span className="text-xs text-muted-foreground">{item.policy_version}</span></div><p className="mt-2 break-all text-sm text-muted-foreground">{item.official_domains.join(", ")}</p><p className="mt-2 text-xs text-muted-foreground">Reviewer {item.reviewer_id} · {item.provenance}</p></article>)}{!brands.length && <EmptyState icon={ShieldCheck} text="Chưa có brand registry record." />}</section><section className="space-y-3"><div><h2 className="font-semibold">Security whitelist</h2><p className="text-xs text-muted-foreground">Domain, URL và contact đã được reviewer phê duyệt.</p></div>{whitelist.map((item) => <article key={item.whitelist_id} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={item.lifecycle} /><StatusBadge value={item.scope} /><strong className="break-all">{item.indicator}</strong></div><p className="mt-2 text-xs text-muted-foreground">{item.policy_version} · reviewer {item.reviewer_id}</p><p className="mt-1 text-xs text-muted-foreground">{item.provenance}</p></article>)}{!whitelist.length && <EmptyState icon={ShieldCheck} text="Chưa có whitelist record." />}</section></div>;
}

function CampaignList({ items, details, expanded, onToggle, onDecide }: { items: CampaignSummaryV3[]; details: Record<string, CampaignDetailV3>; expanded: string | null; onToggle: (id: string) => void; onDecide: (item: CampaignSummaryV3) => void }) {
  if (!items.length) return <EmptyState icon={GitBranch} text="Chưa phát hiện cụm chiến dịch nào." />;
  return <div className="space-y-4">{items.map((item) => { const detail = details[item.campaign_id]; const isOpen = expanded === item.campaign_id; return <article key={item.campaign_id} className="overflow-hidden rounded-2xl border border-border bg-card"><button type="button" aria-expanded={isOpen} onClick={() => onToggle(item.campaign_id)} className="flex w-full items-start gap-4 p-5 text-left hover:bg-muted/30"><span className="grid size-10 shrink-0 place-items-center rounded-xl bg-violet-500/10 text-violet-600"><GitBranch className="size-5" /></span><span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><StatusBadge value={item.reviewer_status} /><span className="text-xs text-muted-foreground">{item.analysis_count} analyses</span></span><span className="mt-2 block font-semibold">{item.hypothesis}</span><span className="mt-1 block text-xs text-muted-foreground">Cửa sổ: {formatDate(item.window_started_at)} → {formatDate(item.window_ended_at)}</span><span className="mt-2 flex flex-wrap gap-2">{item.aggregate_signals.map((signal) => <span key={signal.signal} className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">{signal.signal}: {signal.count}</span>)}</span></span><ChevronDown className={cn("mt-2 size-4 shrink-0 transition-transform", isOpen && "rotate-180")} /></button>{item.reviewer_status === "pending_review" && <button type="button" onClick={() => onDecide(item)} className="mx-5 mb-4 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Review campaign</button>}{isOpen && <div className="border-t border-border bg-muted/20 p-5">{detail ? <div className="grid gap-5 text-sm md:grid-cols-3"><DetailList title="Domains" items={detail.registrable_domains} /><DetailList title="Redirect targets" items={detail.redirect_targets} /><DetailList title="Evidence refs" items={detail.evidence_refs} /></div> : <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Đang tải chi tiết…</div>}</div>}</article>; })}</div>;
}

function SourceRegistryList({ items, discoveries, onCreated }: { items: SourcePolicyRecordV3[]; discoveries: SourceDiscoveryRecordV3[]; onCreated: () => Promise<void> }) {
  const [publisher, setPublisher] = useState("");
  const [pattern, setPattern] = useState("");
  const [saving, setSaving] = useState(false);
  const create = async () => {
    if (!publisher.trim() || !pattern.trim() || saving) return;
    setSaving(true);
    try {
      await getAnalysisApi().createSourcePolicy({
        publisher: publisher.trim(), normalized_pattern: pattern.trim(), tier: "B",
        source_type: "reviewed_news", explicit_deny: false, trusted_claim_review: false,
        allowed_operations: ["search", "read", "compare"], policy_version: `admin-${Date.now()}`,
        effective_from: new Date().toISOString(), effective_to: null, default_freshness_seconds: 21600,
      });
      setPublisher(""); setPattern(""); await onCreated();
    } finally { setSaving(false); }
  };
  const decide = async (item: SourceDiscoveryRecordV3, decision: "promote" | "deny" | "demote") => {
    if (saving) return;
    setSaving(true);
    try {
      await getAnalysisApi().decideSourceDiscovery(item.domain, {
        decision,
        note: `Admin ${decision} từ source discovery dashboard`,
      });
      await onCreated();
    } finally { setSaving(false); }
  };
  return <div className="space-y-6"><div className="grid gap-3 rounded-2xl border border-border bg-card p-5 md:grid-cols-[1fr_1fr_auto]"><input aria-label="Publisher" value={publisher} onChange={(event) => setPublisher(event.target.value)} placeholder="Publisher" className="rounded-xl border border-border bg-background px-3 py-2" /><input aria-label="Domain pattern" value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder="*.example.vn" className="rounded-xl border border-border bg-background px-3 py-2" /><button type="button" disabled={saving || !publisher.trim() || !pattern.trim()} onClick={() => void create()} className="rounded-xl bg-primary px-4 py-2 font-semibold text-primary-foreground disabled:opacity-50">Thêm Tier B</button></div><section className="space-y-3"><h2 className="font-semibold">Domain được Tavily phát hiện ({discoveries.length})</h2>{discoveries.map((item) => { const comparisons = item.curated_comparison_count; const agreement = comparisons ? Math.round(item.curated_agreement_count / comparisons * 100) : 0; return <article key={item.domain} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={item.status} /><strong>{item.publisher}</strong><code className="text-xs text-muted-foreground">{item.domain}</code>{item.eligible_for_auto_promotion && <StatusBadge value="eligible" />}</div><p className="mt-2 text-xs text-muted-foreground">Search {item.search_count} · Extract {item.extract_success_count} · {item.independent_claim_count} claim · đồng thuận {agreement}%/{comparisons} đối chiếu</p><div className="mt-3 flex gap-2">{item.status !== "promoted" && <button disabled={saving} onClick={() => void decide(item, "promote")} className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50">Nâng Tier B</button>}{item.status === "promoted" && <button disabled={saving} onClick={() => void decide(item, "demote")} className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50">Hạ Tier</button>}{item.status !== "denied" && <button disabled={saving} onClick={() => void decide(item, "deny")} className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50">Chặn</button>}</div></article>; })}{!discoveries.length && <EmptyState icon={ExternalLink} text="Chưa có domain Tier C được phát hiện." />}</section><section className="space-y-3"><h2 className="font-semibold">Source Registry ({items.length})</h2>{items.map((item) => <article key={item.source_id} className="rounded-xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge value={`Tier ${item.tier}`} /><strong>{item.publisher}</strong><code className="text-xs text-muted-foreground">{item.normalized_pattern}</code></div><p className="mt-2 text-xs text-muted-foreground">{item.policy_version} · {item.allowed_operations.join(", ")} · reviewer {item.reviewer_id}</p></article>)}</section></div>;
}

function DetailList({ title, items }: { title: string; items: string[] }) {
  return <div><h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3><ul className="mt-2 space-y-1.5">{items.map((item) => <li key={item} className="flex gap-2 break-all"><ExternalLink className="mt-0.5 size-3.5 shrink-0 text-primary" />{item}</li>)}{!items.length && <li className="text-muted-foreground">Không có</li>}</ul></div>;
}

function EmptyState({ icon: Icon, text }: { icon: typeof Scale; text: string }) {
  return <div className="grid place-items-center rounded-2xl border border-dashed border-border py-16 text-center"><Icon className="size-8 text-muted-foreground" /><p className="mt-3 text-sm text-muted-foreground">{text}</p></div>;
}
