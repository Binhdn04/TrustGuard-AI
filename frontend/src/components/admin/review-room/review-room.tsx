"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { BadgeCheck, Gavel, LockKeyhole, Workflow } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { AnalysisApi } from "@/lib/api/analysis-api.types";
import { ApiError } from "@/lib/api/http-analysis-api";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import type {
  SecurityAppealStatusV4,
  SecurityAdminCopilotResponseV4,
  SecurityReportStatusV4,
  SecurityScopeResponseV4,
} from "@/types/generated/api-v4";

import { ActionExecutionPanel } from "./action-execution-panel";
import { CaseReviewPanel } from "./case-review-panel";
import { DecisionPanel, type FeedbackDecision } from "./decision-panel";
import { feedbackKey, ReviewQueue, type FeedbackKind, type FeedbackReviewItem } from "./review-queue";

const PAGE_SIZE = 10;

export function ReviewRoom({
  securityApi = getSecurityAnalysisApi(),
  actionApi = getAnalysisApi(),
}: {
  securityApi?: SecurityAnalysisApi;
  actionApi?: AnalysisApi;
}) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
  const [surface, setSurface] = useState<"feedback" | "actions">("feedback");
  const [kind, setKind] = useState<FeedbackKind>("report");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<FeedbackReviewItem[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<FeedbackReviewItem | null>(null);
  const [analysis, setAnalysis] = useState<SecurityScopeResponseV4 | null>(null);
  const [copilot, setCopilot] = useState<SecurityAdminCopilotResponseV4 | null>(null);
  const [copilotState, setCopilotState] = useState({ loading: false, error: null as string | null });
  const [queueState, setQueueState] = useState({ loading: false, error: null as string | null });
  const [caseState, setCaseState] = useState({ loading: false, error: null as string | null });
  const [decisionState, setDecisionState] = useState({ busy: false, blocked: false, error: null as string | null });
  const generation = useRef({ queue: 0, detail: 0 });

  const loadQueue = useCallback(async () => {
    if (!isAdmin || surface !== "feedback") return;
    const current = ++generation.current.queue;
    setQueueState({ loading: true, error: null });
    try {
      if (kind === "report") {
        const result = await securityApi.listAdminReports({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, ...(query.trim() ? { q: query.trim() } : {}), ...(status !== "all" ? { status: status as SecurityReportStatusV4 } : {}) });
        if (generation.current.queue === current) { setItems(result.items.map((record) => ({ kind: "report", record }))); setTotal(result.total); }
      } else {
        const result = await securityApi.listAdminAppeals({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, ...(query.trim() ? { q: query.trim() } : {}), ...(status !== "all" ? { status: status as SecurityAppealStatusV4 } : {}) });
        if (generation.current.queue === current) { setItems(result.items.map((record) => ({ kind: "appeal", record }))); setTotal(result.total); }
      }
      if (generation.current.queue === current) setQueueState({ loading: false, error: null });
    } catch (caught) {
      if (generation.current.queue === current) setQueueState({ loading: false, error: caught instanceof Error ? caught.message : "Không thể tải feedback queue." });
    }
  }, [isAdmin, kind, page, query, securityApi, status, surface]);

  useEffect(() => { void Promise.resolve().then(loadQueue); }, [loadQueue]);

  const selectFeedback = async (item: FeedbackReviewItem) => {
    const current = ++generation.current.detail;
    setSelected(item);
    setAnalysis(null);
    setCopilot(null);
    setCopilotState({ loading: false, error: null });
    setCaseState({ loading: true, error: null });
    setDecisionState({ busy: false, blocked: false, error: null });
    try {
      const result = await securityApi.getAdminAnalysis(item.record.analysis_id);
      if (generation.current.detail === current) { setAnalysis(result); setCaseState({ loading: false, error: null }); }
    } catch (caught) {
      if (generation.current.detail === current) setCaseState({ loading: false, error: caught instanceof Error ? caught.message : "Không thể tải structured case." });
    }
  };

  const loadCopilot = async (refresh: boolean) => {
    if (!analysis || copilotState.loading) return;
    if (!securityApi.draftAdminCopilot) {
      setCopilotState({ loading: false, error: "Admin Copilot is unavailable in this client." });
      return;
    }
    const analysisId = analysis.analysis_id;
    setCopilotState({ loading: true, error: null });
    try {
      const suggestion = await securityApi.draftAdminCopilot(analysisId, { refresh });
      if (analysis.analysis_id === analysisId) setCopilot(suggestion);
      setCopilotState({ loading: false, error: null });
    } catch (caught) {
      setCopilotState({ loading: false, error: caught instanceof Error ? caught.message : "Unable to load Admin Copilot suggestion." });
    }
  };

  const submitFeedbackDecision = async (decision: FeedbackDecision, note: string) => {
    if (!selected || !analysis || decisionState.busy) return;
    setDecisionState({ busy: true, blocked: false, error: null });
    try {
      if (selected.kind === "report") {
        const record = await securityApi.decideAdminReport(selected.record.report_id, { decision: decision as "approved" | "rejected" | "dismissed", note });
        setSelected({ kind: "report", record });
      } else {
        const record = await securityApi.decideAdminAppeal(selected.record.appeal_id, { outcome: decision as "uphold" | "overturn" | "inconclusive", note });
        setSelected({ kind: "appeal", record });
      }
      setDecisionState({ busy: false, blocked: false, error: null });
      await loadQueue();
    } catch (caught) {
      const conflict = caught instanceof ApiError && caught.status === 409;
      setDecisionState({ busy: false, blocked: conflict, error: conflict ? "Record đã được reviewer khác xử lý. Hàng đợi vừa được tải lại; không gửi lại quyết định." : caught instanceof Error ? caught.message : "Không thể ghi quyết định." });
      if (conflict) await loadQueue();
    }
  };

  const switchKind = (next: FeedbackKind) => {
    generation.current.detail += 1;
    setKind(next); setStatus("all"); setPage(1); setSelected(null); setAnalysis(null); setCopilot(null); setCopilotState({ loading: false, error: null }); setCaseState({ loading: false, error: null }); setDecisionState({ busy: false, blocked: false, error: null });
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Admin access required</h1><p className="mt-2 text-sm text-muted-foreground">Review Room chỉ gọi admin APIs sau khi xác nhận security_admin.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về New case</Link></div>;

  return (
    <div className="space-y-6">
      <header className="border-b border-border/70 pb-6"><p className="micro-label text-primary">ADMIN / HUMAN-IN-THE-LOOP</p><div className="mt-2 flex items-start gap-3"><span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-primary/10 text-primary"><Gavel className="size-5" /></span><div><h1 className="text-3xl font-bold tracking-[-0.025em]">Security Review Room</h1><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Structured, privacy-minimized case evidence before every feedback decision; reviewed actions remain visibly isolated on v3.</p></div></div></header>
      <div className="inline-grid grid-cols-2 rounded-xl bg-muted p-1" role="tablist" aria-label="Review Room surface">
        <button type="button" role="tab" aria-selected={surface === "feedback"} onClick={() => setSurface("feedback")} className={cn("inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold", surface === "feedback" ? "bg-background shadow-sm" : "text-muted-foreground")}><BadgeCheck className="size-4" />Feedback decisions</button>
        <button type="button" role="tab" aria-selected={surface === "actions"} onClick={() => setSurface("actions")} className={cn("inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold", surface === "actions" ? "bg-background shadow-sm" : "text-muted-foreground")}><Workflow className="size-4" />Reviewed actions v3</button>
      </div>

      {surface === "feedback" ? (
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(18rem,0.62fr)_minmax(32rem,1.55fr)_minmax(17rem,0.58fr)]">
          <ReviewQueue kind={kind} items={items} selectedKey={selected ? feedbackKey(selected) : null} query={query} status={status} loading={queueState.loading} error={queueState.error} page={page} total={total} pageSize={PAGE_SIZE} onKindChange={switchKind} onQueryChange={(value) => { setQuery(value); setPage(1); }} onStatusChange={(value) => { setStatus(value); setPage(1); }} onSelect={(item) => void selectFeedback(item)} onPageChange={setPage} onRetry={() => void loadQueue()} />
          <CaseReviewPanel feedback={selected} analysis={analysis} loading={caseState.loading} error={caseState.error} copilot={copilot} copilotLoading={copilotState.loading} copilotError={copilotState.error} onCopilot={(refresh) => void loadCopilot(refresh)} />
          <DecisionPanel key={selected ? feedbackKey(selected) : "empty"} feedback={selected} caseReady={analysis !== null && !caseState.loading && !caseState.error && !decisionState.blocked} busy={decisionState.busy} error={decisionState.error} onSubmit={submitFeedbackDecision} />
        </div>
      ) : <ActionExecutionPanel api={actionApi} />}
    </div>
  );
}
