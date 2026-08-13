"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, MessageSquareWarning, RefreshCw, Shield } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

import { AnalysisAppealForm } from "./analysis-appeal-form";
import { AnalysisLimitations } from "./analysis-limitations";
import { AnalysisReportForm } from "./analysis-report-form";
import { SecurityChatComposer } from "./security-chat-composer";
import { SecurityRiskSummary } from "./security-risk-summary";
import { SecurityTechnicalDetails } from "./security-technical-details";

type SecurityUiState =
  | "IDLE"
  | "RUNNING"
  | "PROVISIONAL_WARNING"
  | "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
  | "NEED_MORE_INFO"
  | "COMPLETED"
  | "FAILED";

interface ChatTurn {
  id: string;
  message: string;
  result: SecurityScopeResponseV4 | null;
}

function stateFor(result: SecurityScopeResponseV4): SecurityUiState {
  if (result.status === "failed") return "FAILED";
  if (result.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") return "OUT_OF_SCOPE_GENERAL_FACT_CHECK";
  if (result.scope_decision === "NEED_MORE_INFO") return "NEED_MORE_INFO";
  if (result.status === "completed") return "COMPLETED";
  return result.risk === "HIGH_RISK" || result.risk === "MALICIOUS" ? "PROVISIONAL_WARNING" : "RUNNING";
}

function messageForError(error: unknown): string {
  return error instanceof Error ? error.message : "Không thể kết nối tới dịch vụ Security Triage.";
}

export function AnalysisWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [state, setState] = useState<SecurityUiState>("IDLE");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [conversation, setConversation] = useState<{ id: string; version: number } | null>(null);
  const subscription = useRef<{ stop(): void } | null>(null);
  const generation = useRef(0);
  const busy = state === "RUNNING" || state === "PROVISIONAL_WARNING";
  const latest = turns.at(-1)?.result ?? null;

  const stopRuntime = useCallback(() => {
    subscription.current?.stop();
    subscription.current = null;
    setTransport("disconnected");
  }, []);

  useEffect(() => () => {
    generation.current += 1;
    subscription.current?.stop();
  }, []);

  const applyResult = useCallback((turnId: string, result: SecurityScopeResponseV4) => {
    setTurns((current) => current.map((turn) => turn.id === turnId ? { ...turn, result } : turn));
    setConversation({ id: result.conversation_id, version: result.conversation_version });
    setState(stateFor(result));
  }, []);

  const monitor = useCallback((turnId: string, analysisId: string, activeGeneration: number) => {
    subscription.current = subscribeToSecurityEvents(api, analysisId, {
      onEvents: (events) => {
        if (activeGeneration !== generation.current) return;
        if (events.some((event) => event.status === "completed" || event.status === "failed")) {
          void api.getAnalysis(analysisId).then((result) => {
            if (activeGeneration === generation.current) {
              applyResult(turnId, result);
              stopRuntime();
            }
          }).catch((pollError) => {
            setError(messageForError(pollError));
            setState("FAILED");
          });
        }
      },
      onTransportChange: setTransport,
      onError: () => undefined,
    });
  }, [api, applyResult, stopRuntime]);

  const submit = async (message: string, externalLookup: boolean, officialLookup: boolean) => {
    generation.current += 1;
    const activeGeneration = generation.current;
    stopRuntime();
    setError(null);
    setState("RUNNING");
    const turnId = crypto.randomUUID();
    setTurns((current) => [...current, { id: turnId, message, result: null }]);
    try {
      const result = await api.createAnalysis({
        message,
        consent: { external_url_lookup: externalLookup, official_source_lookup: officialLookup },
        ...(conversation ? { conversation_id: conversation.id, conversation_version: conversation.version } : {}),
      });
      if (activeGeneration !== generation.current) return;
      applyResult(turnId, result);
      if (result.status === "running" || result.status === "queued") monitor(turnId, result.analysis_id, activeGeneration);
    } catch (submitError) {
      if (activeGeneration !== generation.current) return;
      setError(messageForError(submitError));
      setState("FAILED");
    }
  };

  const reset = () => {
    generation.current += 1;
    stopRuntime();
    setTurns([]);
    setConversation(null);
    setError(null);
    setState("IDLE");
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header className="text-center">
        <span className="mx-auto grid size-14 place-items-center rounded-2xl bg-primary/10 text-primary"><Shield className="size-8" /></span>
        <h1 className="mt-4 text-3xl font-extrabold tracking-tight sm:text-4xl">Trợ lý Security Triage</h1>
        <p className="mx-auto mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Đánh giá tin nhắn, đường link và yêu cầu đáng ngờ liên quan đến phishing, giả mạo hoặc lừa chuyển tiền.</p>
      </header>

      <div aria-live="polite" aria-busy={busy} className="space-y-5">
        {turns.map((turn) => (
          <article key={turn.id} className="space-y-3">
            <div className="ml-auto max-w-[90%] rounded-2xl rounded-br-md bg-primary px-4 py-3 text-sm text-primary-foreground sm:max-w-[75%]"><p className="whitespace-pre-wrap break-words">{turn.message}</p></div>
            {turn.result?.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK" && <div className="max-w-[90%] rounded-2xl rounded-bl-md border border-border bg-card p-4 text-sm"><p className="font-semibold">Nội dung này nằm ngoài phạm vi Security Triage</p><p className="mt-1 text-muted-foreground">{turn.result.boundary_message}</p></div>}
            {turn.result?.scope_decision === "NEED_MORE_INFO" && <div className="max-w-[90%] rounded-2xl rounded-bl-md border border-amber-500/20 bg-amber-500/5 p-4 text-sm"><p className="font-semibold">Cần thêm thông tin</p><p className="mt-1">{turn.result.follow_up_question}</p></div>}
            {turn.result?.scope_decision === "IN_SCOPE" && turn.result.status === "completed" && turn.result.risk && <div className="max-w-[96%]"><SecurityRiskSummary result={turn.result} /></div>}
          </article>
        ))}
      </div>

      {busy && <section role="status" className="rounded-2xl border border-primary/20 bg-primary/5 p-4"><div className="flex items-center gap-3"><span className="size-3 animate-pulse rounded-full bg-primary" /><div><p className="font-semibold">Đang đánh giá rủi ro</p><p className="text-xs text-muted-foreground">Kết nối: {transport.replaceAll("_", " ")}</p></div></div>{state === "PROVISIONAL_WARNING" && <p className="mt-3 flex gap-2 text-sm font-medium text-orange-700"><MessageSquareWarning className="size-5" />Có tín hiệu rủi ro cao tạm thời; chưa coi đây là kết luận cuối.</p>}</section>}
      {error && <div role="alert" className="flex gap-3 rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-700"><AlertCircle className="size-5 shrink-0" /><div><p className="font-semibold">Không thể hoàn tất đánh giá</p><p className="mt-1">{error}</p></div></div>}

      {latest?.scope_decision === "IN_SCOPE" && latest.status === "completed" && <div className="space-y-4"><SecurityTechnicalDetails result={latest} /><AnalysisLimitations limitations={latest.limitations} /><AnalysisReportForm analysisId={latest.analysis_id} securityApi={api} /><AnalysisAppealForm analysisId={latest.analysis_id} securityApi={api} /></div>}

      {!busy && <SecurityChatComposer onSubmit={submit} busy={false} followUp={state === "NEED_MORE_INFO" ? latest?.follow_up_question : null} />}
      {turns.length > 0 && !busy && <div className="flex justify-center"><button type="button" onClick={reset} className="inline-flex items-center gap-2 rounded-full border border-border px-5 py-2.5 text-sm font-semibold hover:bg-muted"><RefreshCw className="size-4" />Bắt đầu trường hợp mới</button></div>}
    </div>
  );
}
