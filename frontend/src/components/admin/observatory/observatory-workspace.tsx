"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { LockKeyhole } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import type {
  SecurityCampaignAuditRecordV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityDomainIntelligencePageV4,
  SecurityThreatIntelligencePageV4,
  SecurityThreatIntelligenceV4,
} from "@/types/generated/api-v4";

import { CampaignPulse, type CampaignPulseQuery } from "./campaign-pulse";
import { DomainExplorer, type DomainExplorerQuery } from "./domain-explorer";
import { RiskComposition } from "./risk-composition";
import { ThreatExplorer, type ThreatExplorerQuery } from "./threat-explorer";

const PAGE_SIZE = 10;

export function ObservatoryWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [domainQuery, setDomainQuery] = useState<DomainExplorerQuery>({ q: "", risk: null, threatType: null, page: 1 });
  const [threatQuery, setThreatQuery] = useState<ThreatExplorerQuery>({ risk: null, page: 1 });
  const [campaignQuery, setCampaignQuery] = useState<CampaignPulseQuery>({ q: "", status: null, page: 1 });
  const [domains, setDomains] = useState<SecurityDomainIntelligencePageV4 | null>(null);
  const [threats, setThreats] = useState<SecurityThreatIntelligencePageV4 | null>(null);
  const [campaigns, setCampaigns] = useState<SecurityCampaignPageV4 | null>(null);
  const [compositionThreats, setCompositionThreats] = useState<SecurityThreatIntelligenceV4[]>([]);
  const [compositionThreatTotal, setCompositionThreatTotal] = useState(0);
  const [memoryTotal, setMemoryTotal] = useState<number | null>(null);
  const [domainState, setDomainState] = useState({ loading: false, error: null as string | null });
  const [threatState, setThreatState] = useState({ loading: false, error: null as string | null });
  const [campaignState, setCampaignState] = useState({ loading: false, error: null as string | null });
  const [compositionState, setCompositionState] = useState({ loading: false, error: null as string | null });
  const [detail, setDetail] = useState<SecurityCampaignRecordV4 | null>(null);
  const [audit, setAudit] = useState<SecurityCampaignAuditRecordV4[]>([]);
  const [detailState, setDetailState] = useState({ loading: false, error: null as string | null });
  const generations = useRef({ domain: 0, threat: 0, campaign: 0, composition: 0, detail: 0 });

  const loadDomains = useCallback(async () => {
    if (!isAdmin) return;
    const generation = ++generations.current.domain;
    setDomainState({ loading: true, error: null });
    try {
      const result = await api.listDomainIntelligence({ limit: PAGE_SIZE, offset: (domainQuery.page - 1) * PAGE_SIZE, ...(domainQuery.q ? { q: domainQuery.q } : {}), ...(domainQuery.risk ? { risk: domainQuery.risk } : {}), ...(domainQuery.threatType ? { threat_type: domainQuery.threatType } : {}) });
      if (generation === generations.current.domain) setDomains(result);
    } catch (error) {
      if (generation === generations.current.domain) setDomainState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải domain intelligence." });
      return;
    }
    if (generation === generations.current.domain) setDomainState({ loading: false, error: null });
  }, [api, domainQuery, isAdmin]);

  const loadThreats = useCallback(async () => {
    if (!isAdmin) return;
    const generation = ++generations.current.threat;
    setThreatState({ loading: true, error: null });
    try {
      const result = await api.listThreatIntelligence({ limit: PAGE_SIZE, offset: (threatQuery.page - 1) * PAGE_SIZE, ...(threatQuery.risk ? { risk: threatQuery.risk } : {}) });
      if (generation === generations.current.threat) setThreats(result);
    } catch (error) {
      if (generation === generations.current.threat) setThreatState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải threat intelligence." });
      return;
    }
    if (generation === generations.current.threat) setThreatState({ loading: false, error: null });
  }, [api, isAdmin, threatQuery]);

  const loadCampaigns = useCallback(async () => {
    if (!isAdmin) return;
    const generation = ++generations.current.campaign;
    setCampaignState({ loading: true, error: null });
    try {
      const result = await api.pageSecurityCampaigns({ limit: PAGE_SIZE, offset: (campaignQuery.page - 1) * PAGE_SIZE, ...(campaignQuery.q ? { q: campaignQuery.q } : {}), ...(campaignQuery.status ? { status: campaignQuery.status } : {}) });
      if (generation === generations.current.campaign) setCampaigns(result);
    } catch (error) {
      if (generation === generations.current.campaign) setCampaignState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải campaigns." });
      return;
    }
    if (generation === generations.current.campaign) setCampaignState({ loading: false, error: null });
  }, [api, campaignQuery, isAdmin]);

  const loadComposition = useCallback(async () => {
    if (!isAdmin) return;
    const generation = ++generations.current.composition;
    setCompositionState({ loading: true, error: null });
    try {
      const [threatPage, memoryPage] = await Promise.all([
        api.listThreatIntelligence({ limit: 100, offset: 0 }),
        api.pageSecurityMemory({ limit: 1, offset: 0 }),
      ]);
      if (generation !== generations.current.composition) return;
      setCompositionThreats(threatPage.items);
      setCompositionThreatTotal(threatPage.total);
      setMemoryTotal(memoryPage.total);
      setCompositionState({ loading: false, error: null });
    } catch (error) {
      if (generation === generations.current.composition) setCompositionState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải composition." });
    }
  }, [api, isAdmin]);

  useEffect(() => { void Promise.resolve().then(loadDomains); }, [loadDomains]);
  useEffect(() => { void Promise.resolve().then(loadThreats); }, [loadThreats]);
  useEffect(() => { void Promise.resolve().then(loadCampaigns); }, [loadCampaigns]);
  useEffect(() => { void Promise.resolve().then(loadComposition); }, [loadComposition]);

  const selectCampaign = async (campaignId: string) => {
    const generation = ++generations.current.detail;
    setDetailState({ loading: true, error: null });
    setDetail(null);
    setAudit([]);
    try {
      const [selected, selectedAudit] = await Promise.all([api.getSecurityCampaign(campaignId), api.listSecurityCampaignAudit(campaignId)]);
      if (generation !== generations.current.detail) return;
      setDetail(selected);
      setAudit(selectedAudit);
      setDetailState({ loading: false, error: null });
    } catch (error) {
      if (generation === generations.current.detail) setDetailState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải campaign detail." });
    }
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Cần quyền quản trị</h1><p className="mt-2 text-sm text-muted-foreground">Bạn không có quyền xem khu vực này.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về trang chính</Link></div>;

  return (
    <div className="space-y-6">
      <header className="border-b border-border/70 pb-4"><h1 className="text-2xl font-bold tracking-[-0.025em] sm:text-3xl">Tổng quan rủi ro</h1><p className="mt-1 text-sm text-muted-foreground">Theo dõi domain, nhóm nguy cơ và chiến dịch nổi bật.</p></header>
      <div className="grid gap-6 xl:grid-cols-[minmax(28rem,1.35fr)_minmax(20rem,0.65fr)]"><DomainExplorer page={domains} query={domainQuery} loading={domainState.loading} error={domainState.error} onQueryChange={setDomainQuery} onRetry={() => void loadDomains()} /><div className="space-y-6"><RiskComposition threats={compositionThreats} threatTotal={compositionThreatTotal} memoryTotal={memoryTotal} loading={compositionState.loading} error={compositionState.error} /><ThreatExplorer page={threats} query={threatQuery} loading={threatState.loading} error={threatState.error} onQueryChange={setThreatQuery} onRetry={() => void loadThreats()} /></div></div>
      <CampaignPulse page={campaigns} query={campaignQuery} loading={campaignState.loading} error={campaignState.error} detail={detail} audit={audit} detailLoading={detailState.loading} detailError={detailState.error} onQueryChange={setCampaignQuery} onRetry={() => void loadCampaigns()} onSelect={(id) => void selectCampaign(id)} />
    </div>
  );
}
