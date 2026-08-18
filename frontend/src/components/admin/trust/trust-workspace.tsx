"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Database, GitBranch, Landmark, LockKeyhole, ShieldCheck } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import type {
  BrandCreateRequestV4, BrandPageV4, BrandRecordV4, SecurityCampaignAuditRecordV4,
  SecurityCampaignPageV4, SecurityCampaignRecordV4, SecurityMemoryAuditRecordV4,
  SecurityMemoryPageV4, SecurityMemoryRecordV4, SecurityMemoryReviewedVerdictV4,
  WhitelistCreateRequestV4, WhitelistPageV4, WhitelistRecordV4,
} from "@/types/generated/api-v4";

import { BrandRegistry, type TrustRegistryQuery } from "./brand-registry";
import { CampaignReview, type CampaignReviewQuery } from "./campaign-review";
import { SecurityMemoryRegistry, type SecurityMemoryQueryState } from "./security-memory-registry";
import { WhitelistRegistry, type WhitelistRegistryQuery } from "./whitelist-registry";

const PAGE_SIZE = 10;
type Surface = "brands" | "whitelist" | "memory" | "campaigns";
type LoadState = { loading: boolean; error: string | null };

export function TrustWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [surface, setSurface] = useState<Surface>("brands");
  const [brandQuery, setBrandQuery] = useState<TrustRegistryQuery>({ q: "", lifecycle: "all", page: 1 });
  const [whitelistQuery, setWhitelistQuery] = useState<WhitelistRegistryQuery>({ q: "", lifecycle: "all", page: 1 });
  const [memoryQuery, setMemoryQuery] = useState<SecurityMemoryQueryState>({ q: "", risk: "all", verdict: "all", page: 1 });
  const [campaignQuery, setCampaignQuery] = useState<CampaignReviewQuery>({ q: "", status: "all", page: 1 });
  const [brands, setBrands] = useState<BrandPageV4 | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistPageV4 | null>(null);
  const [memory, setMemory] = useState<SecurityMemoryPageV4 | null>(null);
  const [campaigns, setCampaigns] = useState<SecurityCampaignPageV4 | null>(null);
  const [selectedMemory, setSelectedMemory] = useState<SecurityMemoryRecordV4 | null>(null);
  const [memoryAudit, setMemoryAudit] = useState<SecurityMemoryAuditRecordV4[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<SecurityCampaignRecordV4 | null>(null);
  const [campaignAudit, setCampaignAudit] = useState<SecurityCampaignAuditRecordV4[]>([]);
  const [state, setState] = useState<LoadState>({ loading: false, error: null });
  const [detailState, setDetailState] = useState<LoadState>({ loading: false, error: null });
  const [busy, setBusy] = useState(false);
  const generations = useRef({ list: 0, detail: 0 });

  const loadBrands = useCallback(async () => {
    if (!isAdmin || surface !== "brands") return;
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageBrands({ limit: PAGE_SIZE, offset: (brandQuery.page - 1) * PAGE_SIZE, ...(brandQuery.q.trim() ? { q: brandQuery.q.trim() } : {}), ...(brandQuery.lifecycle !== "all" ? { lifecycle: brandQuery.lifecycle } : {}) });
      if (generation === generations.current.list) { setBrands(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải brand registry." }); }
  }, [api, brandQuery, isAdmin, surface]);

  const loadWhitelist = useCallback(async () => {
    if (!isAdmin || surface !== "whitelist") return;
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageWhitelist({ limit: PAGE_SIZE, offset: (whitelistQuery.page - 1) * PAGE_SIZE, ...(whitelistQuery.q.trim() ? { q: whitelistQuery.q.trim() } : {}), ...(whitelistQuery.lifecycle !== "all" ? { lifecycle: whitelistQuery.lifecycle } : {}) });
      if (generation === generations.current.list) { setWhitelist(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải whitelist." }); }
  }, [api, isAdmin, surface, whitelistQuery]);

  const loadMemory = useCallback(async () => {
    if (!isAdmin || surface !== "memory") return;
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageSecurityMemory({ limit: PAGE_SIZE, offset: (memoryQuery.page - 1) * PAGE_SIZE, ...(memoryQuery.q.trim() ? { q: memoryQuery.q.trim() } : {}), ...(memoryQuery.risk !== "all" ? { risk: memoryQuery.risk } : {}), ...(memoryQuery.verdict !== "all" ? { verdict: memoryQuery.verdict } : {}) });
      if (generation === generations.current.list) { setMemory(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải Security Memory." }); }
  }, [api, isAdmin, memoryQuery, surface]);

  const loadCampaigns = useCallback(async () => {
    if (!isAdmin || surface !== "campaigns") return;
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageSecurityCampaigns({ limit: PAGE_SIZE, offset: (campaignQuery.page - 1) * PAGE_SIZE, ...(campaignQuery.q.trim() ? { q: campaignQuery.q.trim() } : {}), ...(campaignQuery.status !== "all" ? { status: campaignQuery.status } : {}) });
      if (generation === generations.current.list) { setCampaigns(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải campaigns." }); }
  }, [api, campaignQuery, isAdmin, surface]);

  useEffect(() => { void Promise.resolve().then(loadBrands); }, [loadBrands]);
  useEffect(() => { void Promise.resolve().then(loadWhitelist); }, [loadWhitelist]);
  useEffect(() => { void Promise.resolve().then(loadMemory); }, [loadMemory]);
  useEffect(() => { void Promise.resolve().then(loadCampaigns); }, [loadCampaigns]);

  const mutate = async (operation: () => Promise<unknown>, reload: () => Promise<void>) => {
    setBusy(true); setState((current) => ({ ...current, error: null }));
    try { await operation(); await reload(); }
    catch (error) { setState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu thay đổi trust." })); }
    finally { setBusy(false); }
  };

  const selectMemory = async (record: SecurityMemoryRecordV4) => {
    const generation = ++generations.current.detail; setSelectedMemory(record); setMemoryAudit([]); setDetailState({ loading: true, error: null });
    try { const audit = await api.listSecurityMemoryAudit(record.memory_id); if (generation === generations.current.detail) { setMemoryAudit(audit); setDetailState({ loading: false, error: null }); } }
    catch (error) { if (generation === generations.current.detail) setDetailState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải Memory audit." }); }
  };

  const correctMemory = async (record: SecurityMemoryRecordV4, verdict: SecurityMemoryReviewedVerdictV4, note: string) => {
    setBusy(true); setDetailState((current) => ({ ...current, error: null }));
    try { const updated = await api.correctSecurityMemory(record.memory_id, { verdict, note }); setSelectedMemory(updated); setMemoryAudit(await api.listSecurityMemoryAudit(record.memory_id)); await loadMemory(); }
    catch (error) { setDetailState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu Memory correction." })); }
    finally { setBusy(false); }
  };

  const selectCampaign = async (record: SecurityCampaignRecordV4) => {
    const generation = ++generations.current.detail; setSelectedCampaign(null); setCampaignAudit([]); setDetailState({ loading: true, error: null });
    try { const [detail, audit] = await Promise.all([api.getSecurityCampaign(record.campaign_id), api.listSecurityCampaignAudit(record.campaign_id)]); if (generation === generations.current.detail) { setSelectedCampaign(detail); setCampaignAudit(audit); setDetailState({ loading: false, error: null }); } }
    catch (error) { if (generation === generations.current.detail) setDetailState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải campaign detail." }); }
  };

  const reviewCampaign = async (record: SecurityCampaignRecordV4, decision: "confirmed" | "rejected", note: string) => {
    setBusy(true); setDetailState((current) => ({ ...current, error: null }));
    try { const updated = await api.reviewSecurityCampaign(record.campaign_id, { decision, note }); setSelectedCampaign(updated); setCampaignAudit(await api.listSecurityCampaignAudit(record.campaign_id)); await loadCampaigns(); }
    catch (error) { setDetailState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu campaign review." })); }
    finally { setBusy(false); }
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Admin access required</h1><p className="mt-2 text-sm text-muted-foreground">Trust lifecycle chỉ gọi Security v4 admin APIs.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về New case</Link></div>;

  const tabs: Array<{ id: Surface; label: string; icon: typeof Landmark }> = [
    { id: "brands", label: "Brands", icon: Landmark }, { id: "whitelist", label: "Whitelist", icon: ShieldCheck },
    { id: "memory", label: "Security Memory", icon: Database }, { id: "campaigns", label: "Campaigns", icon: GitBranch },
  ];
  return <div className="space-y-6"><header className="border-b border-border/70 pb-6"><p className="micro-label text-primary">ADMIN / SECURITY V4</p><h1 className="mt-2 text-3xl font-bold tracking-[-0.025em]">Trust Control Center</h1><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Lifecycle-controlled brand and whitelist registries, explainable Memory corrections and campaign review. Every displayed state comes from v4.</p></header><div className="flex gap-1 overflow-x-auto rounded-xl bg-muted p-1" role="tablist" aria-label="Trust surface">{tabs.map(({ id, label, icon: Icon }) => <button key={id} type="button" role="tab" aria-selected={surface === id} onClick={() => { generations.current.detail += 1; setSurface(id); setState({ loading: false, error: null }); setDetailState({ loading: false, error: null }); }} className={cn("inline-flex min-w-fit flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-semibold", surface === id ? "bg-background shadow-sm" : "text-muted-foreground")}><Icon className="size-4" />{label}</button>)}</div>
    {surface === "brands" && <BrandRegistry page={brands} query={brandQuery} loading={state.loading} busy={busy} error={state.error} onQueryChange={setBrandQuery} onCreate={(request: BrandCreateRequestV4) => mutate(() => api.createBrand(request), loadBrands)} onDisable={(record: BrandRecordV4) => mutate(() => api.disableBrand(record.brand_id), loadBrands)} onRetry={loadBrands} />}
    {surface === "whitelist" && <WhitelistRegistry page={whitelist} query={whitelistQuery} loading={state.loading} busy={busy} error={state.error} onQueryChange={setWhitelistQuery} onCreate={(request: WhitelistCreateRequestV4) => mutate(() => api.createWhitelist(request), loadWhitelist)} onDisable={(record: WhitelistRecordV4) => mutate(() => api.disableWhitelist(record.whitelist_id), loadWhitelist)} onRetry={loadWhitelist} />}
    {surface === "memory" && <SecurityMemoryRegistry page={memory} query={memoryQuery} selected={selectedMemory} audit={memoryAudit} loading={state.loading} detailLoading={detailState.loading} busy={busy} error={state.error ?? detailState.error} onQueryChange={setMemoryQuery} onSelect={selectMemory} onCorrect={correctMemory} onRetry={loadMemory} />}
    {surface === "campaigns" && <CampaignReview page={campaigns} query={campaignQuery} selected={selectedCampaign} audit={campaignAudit} loading={state.loading} detailLoading={detailState.loading} busy={busy} error={state.error ?? detailState.error} onQueryChange={setCampaignQuery} onSelect={selectCampaign} onReview={reviewCampaign} onRetry={loadCampaigns} />}
  </div>;
}
