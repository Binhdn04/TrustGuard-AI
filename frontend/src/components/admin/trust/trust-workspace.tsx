"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Ban, Database, GitBranch, Landmark, LockKeyhole, ScanSearch, Settings2, ShieldCheck } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import type {
  BrandCreateRequestV4, BrandPageV4, BrandRecordV4, SecurityCampaignAuditRecordV4,
  IdentityCandidateDecisionRequestV4, IdentityCandidatePageV4, IdentityCandidateV4,
  ManualIdentityCandidateCreateRequestV4,
  SecurityCampaignPageV4, SecurityCampaignRecordV4, SecurityMemoryAuditRecordV4,
  SecurityMemoryPageV4, SecurityMemoryRecordV4, SecurityMemoryReviewedVerdictV4,
  WhitelistCreateRequestV4, WhitelistPageV4, WhitelistRecordV4,
} from "@/types/generated/api-v4";

import { BrandRegistry, type TrustRegistryQuery } from "./brand-registry";
import { BlacklistRegistry } from "./blacklist-registry";
import { CampaignReview, type CampaignReviewQuery } from "./campaign-review";
import { IdentityCandidateQueue, type IdentityCandidateQuery } from "./identity-candidate-queue";
import { SecurityMemoryRegistry, type SecurityMemoryQueryState } from "./security-memory-registry";
import { WhitelistRegistry, type WhitelistRegistryQuery } from "./whitelist-registry";

const PAGE_SIZE = 10;
type Surface = "whitelist" | "blacklist" | "brands" | "identity" | "memory" | "campaigns";
type LoadState = { loading: boolean; error: string | null };

export function TrustWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [surface, setSurface] = useState<Surface>("whitelist");
  const [brandQuery, setBrandQuery] = useState<TrustRegistryQuery>({ q: "", lifecycle: "all", page: 1 });
  const [identityQuery, setIdentityQuery] = useState<IdentityCandidateQuery>({ entity: "", status: "all", relationship: "all", page: 1 });
  const [whitelistQuery, setWhitelistQuery] = useState<WhitelistRegistryQuery>({ q: "", lifecycle: "all", page: 1 });
  const [memoryQuery, setMemoryQuery] = useState<SecurityMemoryQueryState>({ q: "", risk: "all", verdict: "all", page: 1 });
  const [campaignQuery, setCampaignQuery] = useState<CampaignReviewQuery>({ q: "", status: "all", page: 1 });
  const [brands, setBrands] = useState<BrandPageV4 | null>(null);
  const [identityCandidates, setIdentityCandidates] = useState<IdentityCandidatePageV4 | null>(null);
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
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải danh mục nguồn chính thức." }); }
  }, [api, brandQuery, isAdmin, surface]);

  const loadWhitelist = useCallback(async () => {
    if (!isAdmin || surface !== "whitelist") return;
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageWhitelist({ limit: PAGE_SIZE, offset: (whitelistQuery.page - 1) * PAGE_SIZE, ...(whitelistQuery.q.trim() ? { q: whitelistQuery.q.trim() } : {}), ...(whitelistQuery.lifecycle !== "all" ? { lifecycle: whitelistQuery.lifecycle } : {}) });
      if (generation === generations.current.list) { setWhitelist(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải danh sách tin cậy." }); }
  }, [api, isAdmin, surface, whitelistQuery]);

  const loadIdentityCandidates = useCallback(async () => {
    if (!isAdmin || surface !== "identity") return;
    if (!api.pageIdentityCandidates) { setState({ loading: false, error: "API ứng viên định danh hiện không khả dụng." }); return; }
    const generation = ++generations.current.list; setState({ loading: true, error: null });
    try {
      const result = await api.pageIdentityCandidates({ limit: PAGE_SIZE, offset: (identityQuery.page - 1) * PAGE_SIZE, ...(identityQuery.entity.trim() ? { entity: identityQuery.entity.trim() } : {}), ...(identityQuery.status !== "all" ? { status: identityQuery.status as "discovered" | "verified" | "conflicting" | "promoted" | "rejected" | "confirmed_mismatch" } : {}), ...(identityQuery.relationship !== "all" ? { relationship: identityQuery.relationship as "official_controlled" | "parent_organization" | "endorsed_third_party_service" } : {}) });
      if (generation === generations.current.list) { setIdentityCandidates(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải ứng viên định danh." }); }
  }, [api, identityQuery, isAdmin, surface]);

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
    } catch (error) { if (generation === generations.current.list) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải chiến dịch." }); }
  }, [api, campaignQuery, isAdmin, surface]);

  useEffect(() => { void Promise.resolve().then(loadBrands); }, [loadBrands]);
  useEffect(() => { void Promise.resolve().then(loadWhitelist); }, [loadWhitelist]);
  useEffect(() => { void Promise.resolve().then(loadIdentityCandidates); }, [loadIdentityCandidates]);
  useEffect(() => { void Promise.resolve().then(loadMemory); }, [loadMemory]);
  useEffect(() => { void Promise.resolve().then(loadCampaigns); }, [loadCampaigns]);

  const mutate = async (operation: () => Promise<unknown>, reload: () => Promise<void>) => {
    setBusy(true); setState((current) => ({ ...current, error: null }));
    try { await operation(); await reload(); }
    catch (error) { setState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu thay đổi tin cậy." })); }
    finally { setBusy(false); }
  };
  const decideIdentity = async (candidate: IdentityCandidateV4, request: IdentityCandidateDecisionRequestV4) => {
    if (!api.decideIdentityCandidate) { setState({ loading: false, error: "API duyệt định danh hiện không khả dụng." }); return; }
    await mutate(() => api.decideIdentityCandidate!(candidate.association_id, request), loadIdentityCandidates);
  };
  const createManualIdentity = async (request: ManualIdentityCandidateCreateRequestV4) => {
    if (!api.createManualIdentityCandidate) { setState({ loading: false, error: "API tạo định danh thủ công hiện không khả dụng." }); return; }
    await mutate(() => api.createManualIdentityCandidate!(request), loadIdentityCandidates);
  };

  const selectMemory = async (record: SecurityMemoryRecordV4) => {
    const generation = ++generations.current.detail; setSelectedMemory(record); setMemoryAudit([]); setDetailState({ loading: true, error: null });
    try { const audit = await api.listSecurityMemoryAudit(record.memory_id); if (generation === generations.current.detail) { setMemoryAudit(audit); setDetailState({ loading: false, error: null }); } }
    catch (error) { if (generation === generations.current.detail) setDetailState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải lịch sử Security Memory." }); }
  };

  const correctMemory = async (record: SecurityMemoryRecordV4, verdict: SecurityMemoryReviewedVerdictV4, note: string) => {
    setBusy(true); setDetailState((current) => ({ ...current, error: null }));
    try { const updated = await api.correctSecurityMemory(record.memory_id, { verdict, note }); setSelectedMemory(updated); setMemoryAudit(await api.listSecurityMemoryAudit(record.memory_id)); await loadMemory(); }
    catch (error) { setDetailState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu hiệu chỉnh Security Memory." })); }
    finally { setBusy(false); }
  };

  const selectCampaign = async (record: SecurityCampaignRecordV4) => {
    const generation = ++generations.current.detail; setSelectedCampaign(null); setCampaignAudit([]); setDetailState({ loading: true, error: null });
    try { const [detail, audit] = await Promise.all([api.getSecurityCampaign(record.campaign_id), api.listSecurityCampaignAudit(record.campaign_id)]); if (generation === generations.current.detail) { setSelectedCampaign(detail); setCampaignAudit(audit); setDetailState({ loading: false, error: null }); } }
    catch (error) { if (generation === generations.current.detail) setDetailState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải chi tiết chiến dịch." }); }
  };

  const reviewCampaign = async (record: SecurityCampaignRecordV4, decision: "confirmed" | "rejected", note: string) => {
    setBusy(true); setDetailState((current) => ({ ...current, error: null }));
    try { const updated = await api.reviewSecurityCampaign(record.campaign_id, { decision, note }); setSelectedCampaign(updated); setCampaignAudit(await api.listSecurityCampaignAudit(record.campaign_id)); await loadCampaigns(); }
    catch (error) { setDetailState((current) => ({ ...current, error: error instanceof Error ? error.message : "Không thể lưu kết quả duyệt chiến dịch." })); }
    finally { setBusy(false); }
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Cần quyền quản trị</h1><p className="mt-2 text-sm text-muted-foreground">Bạn không có quyền xem khu vực này.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về trang chính</Link></div>;

  const selectSurface = (id: Surface) => { generations.current.detail += 1; setSurface(id); setState({ loading: false, error: null }); setDetailState({ loading: false, error: null }); };
  const tabs: Array<{ id: Surface; label: string; icon: typeof Landmark }> = [
    { id: "whitelist", label: "Tin cậy", icon: ShieldCheck },
    { id: "blacklist", label: "Chặn", icon: Ban },
  ];
  return <div className="space-y-6"><header className="border-b border-border/70 pb-4"><h1 className="text-2xl font-bold tracking-[-0.025em] sm:text-3xl">Danh sách tin cậy & chặn</h1><p className="mt-1 text-sm text-muted-foreground">Quản lý ngoại lệ tin cậy và domain chặn đã qua người duyệt. Nguồn chính thức không tự xác minh người gửi, hành động hoặc tài nguyên cụ thể.</p></header><div className="flex gap-1 overflow-x-auto rounded-xl bg-muted p-1" role="tablist" aria-label="Danh sách tin cậy và chặn">{tabs.map(({ id, label, icon: Icon }) => <button key={id} type="button" role="tab" aria-selected={surface === id} onClick={() => selectSurface(id)} className={cn("inline-flex min-w-fit flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-semibold", surface === id ? "bg-background shadow-sm" : "text-muted-foreground")}><Icon className="size-4" />{label}</button>)}</div>
    <details className="rounded-xl border border-border bg-card/60 p-3"><summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-semibold"><Settings2 className="size-4" />Nguồn chính thức và công cụ nâng cao</summary><p className="mt-2 text-xs text-muted-foreground">Thương hiệu/định danh phục vụ danh mục đã duyệt; Security Memory/chiến dịch là công cụ chuyên sâu và không phải danh sách tin cậy.</p><div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={() => selectSurface("brands")} className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><Landmark className="mr-1 inline size-3" />Nguồn chính thức</button><button type="button" onClick={() => selectSurface("identity")} className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><ScanSearch className="mr-1 inline size-3" />Duyệt định danh</button><button type="button" onClick={() => selectSurface("memory")} className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><Database className="mr-1 inline size-3" />Security Memory</button><button type="button" onClick={() => selectSurface("campaigns")} className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><GitBranch className="mr-1 inline size-3" />Chiến dịch</button></div></details>
    {surface === "brands" && <BrandRegistry page={brands} query={brandQuery} loading={state.loading} busy={busy} error={state.error} onQueryChange={setBrandQuery} onCreate={(request: BrandCreateRequestV4) => mutate(() => api.createBrand(request), loadBrands)} onCreateVersion={(brandId: string, request: BrandCreateRequestV4) => mutate(() => api.createBrandVersion(brandId, request), loadBrands)} onDisable={(record: BrandRecordV4) => mutate(() => api.disableBrand(record.brand_id), loadBrands)} onRetry={loadBrands} />}
    {surface === "identity" && <IdentityCandidateQueue page={identityCandidates} query={identityQuery} loading={state.loading} busy={busy} error={state.error} onQueryChange={setIdentityQuery} onCreateManual={createManualIdentity} onDecide={decideIdentity} onRetry={loadIdentityCandidates} />}
    {surface === "whitelist" && <WhitelistRegistry page={whitelist} query={whitelistQuery} loading={state.loading} busy={busy} error={state.error} onQueryChange={setWhitelistQuery} onCreate={(request: WhitelistCreateRequestV4) => mutate(() => api.createWhitelist(request), loadWhitelist)} onDisable={(record: WhitelistRecordV4) => mutate(() => api.disableWhitelist(record.whitelist_id), loadWhitelist)} onAudit={async (record) => (await api.listAdminAudit({ resource_type: "whitelist", limit: 100 })).items.filter((item) => item.resource_id === record.whitelist_id)} onRetry={loadWhitelist} />}
    {surface === "blacklist" && <BlacklistRegistry api={api} />}
    {surface === "memory" && <SecurityMemoryRegistry page={memory} query={memoryQuery} selected={selectedMemory} audit={memoryAudit} loading={state.loading} detailLoading={detailState.loading} busy={busy} error={state.error ?? detailState.error} onQueryChange={setMemoryQuery} onSelect={selectMemory} onCorrect={correctMemory} onRetry={loadMemory} />}
    {surface === "campaigns" && <CampaignReview page={campaigns} query={campaignQuery} selected={selectedCampaign} audit={campaignAudit} loading={state.loading} detailLoading={detailState.loading} busy={busy} error={state.error ?? detailState.error} onQueryChange={setCampaignQuery} onSelect={selectCampaign} onReview={reviewCampaign} onRetry={loadCampaigns} />}
  </div>;
}
