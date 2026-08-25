"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { LockKeyhole } from "lucide-react";

import { ApiError } from "@/lib/api/api-error";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import type {
  SecurityAppealStatusV4,
  SecurityAdminCopilotResponseV4,
  SecurityReportStatusV4,
  SecurityScopeResponseV4,
} from "@/types/generated/api-v4";

import { CaseReviewPanel } from "./case-review-panel";
import { DecisionPanel, type FeedbackDecisionSubmission } from "./decision-panel";
import { feedbackKey, ReviewQueue, type FeedbackKind, type FeedbackReviewItem } from "./review-queue";

const PAGE_SIZE = 10;

export function ReviewRoom({ securityApi = getSecurityAnalysisApi() }: { securityApi?: SecurityAnalysisApi }) {
  const { user, isLoading: authLoading } = useAuth();
  const isAdmin = user?.role === "security_admin";
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
    if (!isAdmin) return;
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
      if (generation.current.queue === current) setQueueState({ loading: false, error: caught instanceof Error ? caught.message : "Không thể tải hàng đợi phản hồi." });
    }
  }, [isAdmin, kind, page, query, securityApi, status]);

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
      if (generation.current.detail === current) setCaseState({ loading: false, error: caught instanceof Error ? caught.message : "Không thể tải hồ sơ có cấu trúc." });
    }
  };

  const loadCopilot = async (refresh: boolean) => {
    if (!analysis || copilotState.loading) return;
    if (!securityApi.draftAdminCopilot) {
      setCopilotState({ loading: false, error: "Admin Copilot hiện không khả dụng trên giao diện này." });
      return;
    }
    const analysisId = analysis.analysis_id;
    setCopilotState({ loading: true, error: null });
    try {
      const suggestion = await securityApi.draftAdminCopilot(analysisId, { refresh });
      if (analysis.analysis_id === analysisId) setCopilot(suggestion);
      setCopilotState({ loading: false, error: null });
    } catch (caught) {
      setCopilotState({ loading: false, error: caught instanceof Error ? caught.message : "Không thể tải gợi ý của Admin Copilot." });
    }
  };

  const submitFeedbackDecision = async (submission: FeedbackDecisionSubmission) => {
    if (!selected || !analysis || decisionState.busy) return;
    setDecisionState({ busy: true, blocked: false, error: null });
    try {
      if (selected.kind === "report") {
        if (submission.kind !== "report") return;
        const record = await securityApi.decideAdminReport(selected.record.report_id, submission.request);
        setSelected({ kind: "report", record });
      } else {
        if (submission.kind !== "appeal") return;
        const record = await securityApi.decideAdminAppeal(selected.record.appeal_id, { outcome: submission.decision, note: submission.note });
        setSelected({ kind: "appeal", record });
      }
      setDecisionState({ busy: false, blocked: false, error: null });
      await loadQueue();
    } catch (caught) {
      const conflict = caught instanceof ApiError && caught.status === 409;
      setDecisionState({ busy: false, blocked: conflict, error: conflict ? "Hồ sơ đã được người duyệt khác xử lý. Hàng đợi vừa được tải lại; không gửi lại quyết định." : caught instanceof Error ? caught.message : "Không thể ghi quyết định." });
      if (conflict) await loadQueue();
    }
  };

  const decideLinkedBlacklist = async (actionId: string, decision: "approved" | "rejected") => {
    if (!selected || selected.kind !== "report" || decisionState.busy) return;
    if (!securityApi.decideBlacklistAction) {
      setDecisionState({ busy: false, blocked: false, error: "Client hiện tại chưa hỗ trợ quyết định danh sách chặn v4." });
      return;
    }
    setDecisionState({ busy: true, blocked: false, error: null });
    try {
      const result = await securityApi.decideBlacklistAction(actionId, {
        decision,
        note: `${decision === "approved" ? "Xác nhận thực thi" : "Từ chối"} đề xuất chặn từ báo cáo ${selected.record.report_id}: ${selected.record.review_note ?? "đã rà soát bằng chứng"}`,
      });
      const remediationStatus = result.status === "executed" ? "executed" : "failed";
      setSelected({
        kind: "report",
        record: {
          ...selected.record,
          remediation_status: remediationStatus,
          remediation_reference: { admin_action_id: actionId },
        },
      });
      setDecisionState({
        busy: false,
        blocked: false,
        error: result.status === "failed" ? result.execution_error ?? "Thực thi hành động chặn thất bại." : null,
      });
      await loadQueue();
    } catch (caught) {
      const conflict = caught instanceof ApiError && caught.status === 409;
      setDecisionState({
        busy: false,
        blocked: conflict,
        error: conflict
          ? "Action đã được người duyệt khác xử lý. Hàng đợi vừa được tải lại; không gửi lại quyết định."
          : caught instanceof Error ? caught.message : "Không thể xử lý đề xuất chặn.",
      });
      if (conflict) await loadQueue();
    }
  };

  const switchKind = (next: FeedbackKind) => {
    generation.current.detail += 1;
    setKind(next); setStatus("all"); setPage(1); setSelected(null); setAnalysis(null); setCopilot(null); setCopilotState({ loading: false, error: null }); setCaseState({ loading: false, error: null }); setDecisionState({ busy: false, blocked: false, error: null });
  };

  if (authLoading) return <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang xác minh quyền truy cập…</p>;
  if (!isAdmin) return <div className="mx-auto max-w-xl py-12 text-center"><LockKeyhole className="mx-auto size-8 text-muted-foreground" /><h1 className="mt-3 text-xl font-semibold">Cần quyền quản trị</h1><p className="mt-2 text-sm text-muted-foreground">Bạn không có quyền xem khu vực này.</p><Link href="/" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Về trang chính</Link></div>;

  return (
    <div className="space-y-6">
      <header className="border-b border-border/70 pb-4"><h1 className="text-2xl font-bold tracking-[-0.025em] sm:text-3xl">Duyệt bảo mật</h1><p className="mt-1 text-sm text-muted-foreground">Đưa ra kết luận có cấu trúc và chọn hướng khắc phục rõ ràng cho báo cáo hoặc khiếu nại.</p></header>
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(18rem,0.62fr)_minmax(32rem,1.55fr)_minmax(17rem,0.58fr)]">
          <ReviewQueue kind={kind} items={items} selectedKey={selected ? feedbackKey(selected) : null} query={query} status={status} loading={queueState.loading} error={queueState.error} page={page} total={total} pageSize={PAGE_SIZE} onKindChange={switchKind} onQueryChange={(value) => { setQuery(value); setPage(1); }} onStatusChange={(value) => { setStatus(value); setPage(1); }} onSelect={(item) => void selectFeedback(item)} onPageChange={setPage} onRetry={() => void loadQueue()} />
          <CaseReviewPanel feedback={selected} analysis={analysis} loading={caseState.loading} error={caseState.error} copilot={copilot} copilotLoading={copilotState.loading} copilotError={copilotState.error} onCopilot={(refresh) => void loadCopilot(refresh)} />
          <DecisionPanel key={selected ? feedbackKey(selected) : "empty"} feedback={selected} analysis={analysis} caseReady={analysis !== null && !caseState.loading && !caseState.error && !decisionState.blocked} busy={decisionState.busy} error={decisionState.error} onSubmit={submitFeedbackDecision} onBlacklistDecision={decideLinkedBlacklist} />
      </div>
    </div>
  );
}
