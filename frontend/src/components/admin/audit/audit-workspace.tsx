"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { FileClock, LockKeyhole } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import type { SecurityAdminAuditPageV4 } from "@/types/generated/api-v4";

import { UnifiedAuditList, type UnifiedAuditQuery } from "./unified-audit-list";

const PAGE_SIZE = 20;

export function AuditWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [query, setQuery] = useState<UnifiedAuditQuery>({ resourceType: "all", action: "", page: 1 });
  const [page, setPage] = useState<SecurityAdminAuditPageV4 | null>(null);
  const [state, setState] = useState({ loading: false, error: null as string | null });
  const generation = useRef(0);
  const load = useCallback(async () => {
    if (!isAdmin) return;
    const current = ++generation.current; setState({ loading: true, error: null });
    try {
      const result = await api.listAdminAudit({ limit: PAGE_SIZE, offset: (query.page - 1) * PAGE_SIZE, ...(query.resourceType !== "all" ? { resource_type: query.resourceType } : {}), ...(query.action.trim() ? { action: query.action.trim() } : {}) });
      if (generation.current === current) { setPage(result); setState({ loading: false, error: null }); }
    } catch (error) { if (generation.current === current) setState({ loading: false, error: error instanceof Error ? error.message : "Không thể tải unified audit." }); }
  }, [api, isAdmin, query]);
  useEffect(() => { void Promise.resolve().then(load); }, [load]);
  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Admin access required</h1><p className="mt-2 text-sm text-muted-foreground">Unified audit chỉ đọc v4 admin events.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về New case</Link></div>;
  return <div className="space-y-6"><header className="border-b border-border/70 pb-6"><p className="micro-label text-primary">ADMIN / SECURITY V4</p><div className="mt-2 flex items-start gap-3"><span className="grid size-11 place-items-center rounded-2xl bg-primary/10 text-primary"><FileClock className="size-5" /></span><div><h1 className="text-3xl font-bold tracking-[-0.025em]">Unified Audit</h1><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">A single v4 audit stream for trust, memory, campaign and feedback review. No fabricated before/after diff.</p></div></div></header><UnifiedAuditList page={page} query={query} loading={state.loading} error={state.error} onQueryChange={setQuery} onRetry={load} /></div>;
}
