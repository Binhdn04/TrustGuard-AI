"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, FileQuestion, Loader2, Plus, RotateCw } from "lucide-react";

import { ActionRiskPanel } from "@/components/analysis/action-risk-panel";
import { AnalysisAppealForm } from "@/components/analysis/analysis-appeal-form";
import { AnalysisLimitations } from "@/components/analysis/analysis-limitations";
import { AnalysisReportForm } from "@/components/analysis/analysis-report-form";
import { CaseSignalMap } from "@/components/analysis/case-signal-map";
import { EvidenceDeck } from "@/components/analysis/evidence-deck";
import { InvestigationTimelineV4 } from "@/components/analysis/investigation-timeline-v4";
import { SimpleAnalystToggle } from "@/components/analysis/simple-analyst-toggle";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import { AUTOMATIC_LOOKUP_CONSENT } from "@/lib/security/automatic-lookup-policy";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import { ApiError } from "@/lib/api/api-error";
import { mapSecurityCaseViewModel, type SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type { SecurityAnalysisEventV4, SecurityConversationV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

import { ResumedContextCard } from "./resumed-context-card";

function unavailableMessage(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  if (error.status === 403) return "Bạn không có quyền mở conversation này. Hãy bắt đầu một case mới nếu cần tiếp tục.";
  if (error.status === 404) return "Conversation đã hết hạn hoặc không còn tồn tại. Case vẫn ở chế độ chỉ đọc; bạn có thể bắt đầu case mới.";
  return null;
}

function caseLoadMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) return "Bạn không có quyền mở analysis này.";
  if (error instanceof ApiError && error.status === 404) return "Analysis không tồn tại hoặc không còn khả dụng.";
  return error instanceof Error ? error.message : "Không thể tải case.";
}

export function CaseDetail({
  analysisId,
  api = getSecurityAnalysisApi(),
}: {
  analysisId: string;
  api?: SecurityAnalysisApi;
}) {
  const router = useRouter();
  const [result, setResult] = useState<SecurityScopeResponseV4 | null>(null);
  const [conversation, setConversation] = useState<SecurityConversationV4 | null>(null);
  const [events, setEvents] = useState<SecurityAnalysisEventV4[]>([]);
  const [mode, setMode] = useState<SecurityPresentationMode>("simple");
  const [loading, setLoading] = useState(true);
  const [resumeBusy, setResumeBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resumeIssue, setResumeIssue] = useState<string | null>(null);
  const generation = useRef(0);
  const subscription = useRef<{ stop(): void } | null>(null);

  const stopRuntime = useCallback(() => {
    subscription.current?.stop();
    subscription.current = null;
  }, []);

  const monitor = useCallback((activeAnalysisId: string, activeGeneration: number) => {
    stopRuntime();
    subscription.current = subscribeToSecurityEvents(api, activeAnalysisId, {
      onEvents: (nextEvents) => {
        if (activeGeneration !== generation.current) return;
        setEvents((current) => {
          const byId = new Map(current.map((event) => [event.event_id, event]));
          nextEvents.forEach((event) => byId.set(event.event_id, event));
          return [...byId.values()].sort((left, right) => left.sequence - right.sequence);
        });
        if (!nextEvents.some((event) => event.status === "completed" || event.status === "failed")) return;
        void api.getAnalysis(activeAnalysisId).then((terminal) => {
          if (activeGeneration !== generation.current) return;
          setResult(terminal);
          setResumeBusy(false);
          stopRuntime();
        }).catch((terminalError: unknown) => {
          if (activeGeneration !== generation.current) return;
          setResumeIssue(terminalError instanceof Error ? terminalError.message : "Không thể tải kết quả follow-up.");
          setResumeBusy(false);
          stopRuntime();
        });
      },
      onTransportChange: () => undefined,
      onError: () => undefined,
    });
  }, [api, stopRuntime]);

  const load = useCallback(async () => {
    const activeGeneration = ++generation.current;
    stopRuntime();
    setLoading(true);
    setError(null);
    setResumeIssue(null);
    try {
      const analysis = await api.getAnalysis(analysisId);
      if (activeGeneration !== generation.current) return;
      setResult(analysis);
      const [eventResult, conversationResult] = await Promise.allSettled([
        api.getAnalysisEvents(analysis.analysis_id, { limit: 100 }),
        api.getConversation(analysis.conversation_id),
      ]);
      if (activeGeneration !== generation.current) return;
      setEvents(eventResult.status === "fulfilled" ? eventResult.value.events : []);
      if (conversationResult.status === "fulfilled") {
        setConversation(conversationResult.value);
        if (conversationResult.value.status !== "active") {
          setResumeIssue("Conversation đã hết hạn. Case vẫn ở chế độ chỉ đọc; hãy bắt đầu case mới để tiếp tục.");
        }
      } else {
        setConversation(null);
        setResumeIssue(unavailableMessage(conversationResult.reason) ?? "Không thể tải structured conversation context.");
      }
      if (analysis.status === "queued" || analysis.status === "running") monitor(analysis.analysis_id, activeGeneration);
    } catch (loadError) {
      if (activeGeneration !== generation.current) return;
      setError(caseLoadMessage(loadError));
    } finally {
      if (activeGeneration === generation.current) setLoading(false);
    }
  }, [analysisId, api, monitor, stopRuntime]);

  useEffect(() => {
    void Promise.resolve().then(load);
    return () => {
      generation.current += 1;
      stopRuntime();
    };
  }, [load, stopRuntime]);

  const resume = async (message: string): Promise<boolean> => {
    if (!conversation) return false;
    const activeGeneration = ++generation.current;
    stopRuntime();
    setResumeBusy(true);
    setResumeIssue(null);
    try {
      const next = await api.createAnalysis({
        message,
        conversation_id: conversation.conversation_id,
        conversation_version: conversation.context_version,
        consent: AUTOMATIC_LOOKUP_CONSENT,
      });
      if (activeGeneration !== generation.current) return false;
      if (!("scope_decision" in next)) {
        setEvents([]);
        router.replace(`/cases/${encodeURIComponent(next.analysis_id)}`);
        setConversation(await api.getConversation(next.conversation_id));
        monitor(next.analysis_id, activeGeneration);
        return true;
      }
      setResult(next);
      setEvents([]);
      router.replace(`/cases/${encodeURIComponent(next.analysis_id)}`);
      try {
        setConversation(await api.getConversation(next.conversation_id));
      } catch {
        setConversation((current) => current ? { ...current, context_version: next.conversation_version, active_analysis_id: next.analysis_id, summary: { ...current.summary, security_context: next.security_context } } : current);
      }
      if (next.status === "queued" || next.status === "running") {
        monitor(next.analysis_id, activeGeneration);
      } else {
        setResumeBusy(false);
      }
      return true;
    } catch (resumeError) {
      if (activeGeneration !== generation.current) return false;
      if (resumeError instanceof ApiError && resumeError.status === 409) {
        try {
          const refreshed = await api.getConversation(conversation.conversation_id);
          if (activeGeneration === generation.current) setConversation(refreshed);
          setResumeIssue("Case đã được cập nhật ở một lượt khác. Context version mới đã được tải; hãy kiểm tra rồi gửi lại follow-up.");
        } catch (refreshError) {
          setConversation(null);
          setResumeIssue(unavailableMessage(refreshError) ?? "Không thể làm mới conversation sau version conflict. Hãy bắt đầu case mới.");
        }
      } else {
        const unavailable = unavailableMessage(resumeError);
        if (unavailable) setConversation(null);
        setResumeIssue(unavailable ?? (resumeError instanceof Error ? resumeError.message : "Không thể tiếp tục case."));
      }
      setResumeBusy(false);
      return false;
    }
  };

  const viewModel = useMemo(() => result ? mapSecurityCaseViewModel(result, events) : null, [events, result]);

  if (loading) return <div role="status" className="grid min-h-[28rem] place-items-center"><span className="inline-flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-5 animate-spin" />Đang tải case</span></div>;

  if (error || !result) {
    return (
      <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6">
        <div role="alert" className="case-panel p-6 text-center">
          <FileQuestion className="mx-auto size-7 text-muted-foreground" />
          <h1 className="mt-3 text-xl font-semibold">Không thể mở case</h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">{error ?? "Case không tồn tại."}</p>
          <div className="mt-5 flex flex-wrap justify-center gap-3">
            <button type="button" onClick={() => void load()} className="inline-flex items-center gap-2 rounded-xl border border-border px-4 py-2 text-sm font-semibold"><RotateCw className="size-4" />Thử lại</button>
            <Link href="/" className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Bắt đầu case mới</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl space-y-5 px-4 py-8 sm:px-6">
      <header className="flex flex-col justify-between gap-4 border-b border-border/70 pb-5 sm:flex-row sm:items-end">
        <div>
          <Link href="/history" className="inline-flex items-center gap-1 text-xs font-semibold text-muted-foreground hover:text-foreground"><ArrowLeft className="size-4" />Case library</Link>
          <p className="micro-label mt-4 text-primary">CASE DETAIL / {result.analysis_id.slice(0, 8)}</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-[-0.025em]">Security investigation record</h1>
          <p className="mt-1 text-xs text-muted-foreground">{result.status} · {result.scope_decision} · <time dateTime={result.created_at}>{new Date(result.created_at).toLocaleString("vi-VN")}</time></p>
        </div>
        <div className="flex flex-wrap gap-2"><SimpleAnalystToggle mode={mode} onChange={setMode} /><Link href="/" className="inline-flex items-center gap-2 rounded-xl border border-border bg-card px-3.5 py-2 text-xs font-semibold"><Plus className="size-3.5" />Case mới</Link></div>
      </header>

      {result.scope_decision === "IN_SCOPE" && viewModel ? (
        <div className="grid gap-5 xl:grid-cols-[minmax(22rem,0.85fr)_minmax(28rem,1.15fr)]">
          <div className="space-y-5">
            {result.risk && <div className="case-panel p-5"><ActionRiskPanel viewModel={viewModel} mode={mode} /></div>}
            <ResumedContextCardOrIssue conversation={conversation} busy={resumeBusy} issue={resumeIssue} onResume={resume} />
            {result.risk && <div className="case-panel space-y-4 p-5"><AnalysisReportForm analysisId={result.analysis_id} securityApi={api} /><AnalysisAppealForm analysisId={result.analysis_id} securityApi={api} /></div>}
          </div>
          <section aria-label="Investigation details" className="case-panel space-y-7 p-5">
            <CaseSignalMap nodes={viewModel.signalNodes} edges={viewModel.signalEdges} mode={mode} />
            <InvestigationTimelineV4 lifecycle={viewModel.lifecycle} steps={viewModel.steps} errors={viewModel.errors} mode={mode} />
            <EvidenceDeck evidence={viewModel.evidence} mode={mode} />
            <AnalysisLimitations limitations={result.limitations} />
          </section>
        </div>
      ) : (
        <div className="grid gap-5 lg:grid-cols-2">
          <section className="case-panel p-5">
            <p className="micro-label">Scope result</p>
            <h2 className="mt-2 text-lg font-semibold">{result.scope_decision === "NEED_MORE_INFO" ? "Cần thêm thông tin" : "Ngoài phạm vi Security Triage"}</h2>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{result.follow_up_question ?? result.boundary_message ?? "API chưa trả thông điệp bổ sung."}</p>
          </section>
          <ResumedContextCardOrIssue conversation={conversation} busy={resumeBusy} issue={resumeIssue} onResume={resume} />
        </div>
      )}
    </div>
  );
}

function ResumedContextCardOrIssue({
  conversation,
  busy,
  issue,
  onResume,
}: {
  conversation: SecurityConversationV4 | null;
  busy: boolean;
  issue: string | null;
  onResume(message: string): Promise<boolean>;
}) {
  if (conversation) return <ResumedContextCard conversation={conversation} busy={busy} issue={issue} onResume={onResume} />;
  return (
    <section aria-labelledby="resume-unavailable-heading" className="case-panel p-5">
      <p className="micro-label">PRIVACY-SAFE RESUME</p>
      <h2 id="resume-unavailable-heading" className="mt-2 text-base font-semibold">Không thể tiếp tục conversation</h2>
      <p role="alert" className="mt-2 text-sm leading-6 text-muted-foreground">{issue ?? "Structured conversation context không khả dụng."}</p>
      <Link href="/" className="mt-4 inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Bắt đầu case mới</Link>
    </section>
  );
}
