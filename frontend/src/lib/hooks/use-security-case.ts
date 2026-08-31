"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "@/lib/api/api-error";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import { selectSecurityProgress } from "@/lib/security-progress";
import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityAnalysisEventV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

export type SecurityCaseState =
  | "IDLE"
  | "CHATTING"
  | "RUNNING"
  | "PROVISIONAL_WARNING"
  | "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
  | "NEED_MORE_INFO"
  | "COMPLETED"
  | "FAILED";

export interface SecurityCaseSubmission {
  message: string;
}

export interface SecurityCaseTurn extends SecurityCaseSubmission {
  id: string;
  analysisId?: string;
  idempotencyKey: string;
  result: SecurityScopeResponseV4 | null;
  chatResponse?: string;
}

export type SecurityCaseRecoveryAction = "reload_and_resubmit" | "start_new_case" | null;

function stateFor(result: SecurityScopeResponseV4): SecurityCaseState {
  if (result.status === "failed") return "FAILED";
  if (result.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") {
    return "OUT_OF_SCOPE_GENERAL_FACT_CHECK";
  }
  if (result.scope_decision === "NEED_MORE_INFO") return "NEED_MORE_INFO";
  if (result.status === "completed") return "COMPLETED";
  return result.risk === "HIGH_RISK" || result.risk === "MALICIOUS"
    ? "PROVISIONAL_WARNING"
    : "RUNNING";
}

function messageForError(error: unknown): string {
  if (error instanceof ApiError && error.code === "VALIDATION_ERROR") {
    const errors: unknown[] = Array.isArray(error.details.errors) ? error.details.errors : [];
    const fields = errors
      .map((item) => {
        if (!item || typeof item !== "object" || !("loc" in item)) return null;
        const location = (item as { loc: unknown }).loc;
        if (!Array.isArray(location)) return null;
        return location.filter((part: unknown): part is string | number => (
          typeof part === "string" || typeof part === "number"
        )).join(".");
      })
      .filter((field): field is string => Boolean(field));
    if (fields.length) {
      return `Dữ liệu gửi lên không tương thích ở trường: ${[...new Set(fields)].join(", ")}.`;
    }
  }
  return error instanceof ApiError
    ? error.message
    : "Không thể hoàn tất đánh giá. Vui lòng thử lại.";
}

function mergeLifecycleEvents(
  current: SecurityAnalysisEventV4[],
  incoming: SecurityAnalysisEventV4[],
): SecurityAnalysisEventV4[] {
  const byEventId = new Map(current.map((event) => [event.event_id, event]));
  incoming.forEach((event) => byEventId.set(event.event_id, event));
  return [...byEventId.values()].sort((left, right) => left.sequence - right.sequence);
}

export function useSecurityCase(
  api: SecurityAnalysisApi,
  consent: { external_url_lookup: boolean; official_source_lookup: boolean } = { external_url_lookup: false, official_source_lookup: false },
) {
  const [turns, setTurns] = useState<SecurityCaseTurn[]>([]);
  const [state, setState] = useState<SecurityCaseState>("IDLE");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [recoveryAction, setRecoveryAction] = useState<SecurityCaseRecoveryAction>(null);
  const [lifecycleEvents, setLifecycleEvents] = useState<SecurityAnalysisEventV4[]>([]);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);
  const [conversation, setConversation] = useState<{ id: string; version: number } | null>(null);
  const subscription = useRef<{ stop(): void } | null>(null);
  const generation = useRef(0);
  const mounted = useRef(true);

  const stopRuntime = useCallback(() => {
    subscription.current?.stop();
    subscription.current = null;
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
      subscription.current?.stop();
    };
  }, []);

  const applyResult = useCallback((turnId: string, result: SecurityScopeResponseV4) => {
    setTurns((current) => current.map((turn) => (
      turn.id === turnId ? { ...turn, analysisId: undefined, result } : turn
    )));
    setConversation({ id: result.conversation_id, version: result.conversation_version });
    setState(stateFor(result));
    setActiveAnalysisId(null);
    setRecoveryAction(null);
  }, []);

  const monitor = useCallback((turnId: string, analysisId: string, activeGeneration: number) => {
    let resolvingTerminal = false;
    subscription.current = subscribeToSecurityEvents(api, analysisId, {
      onEvents: (events) => {
        if (!mounted.current || activeGeneration !== generation.current) return;
        setLifecycleEvents((current) => mergeLifecycleEvents(current, events));
        if (events.some((event) => event.kind === "provisional")) {
          setState("PROVISIONAL_WARNING");
        }
        const terminal = events.some((event) => event.status === "completed" || event.status === "failed");
        if (!terminal || resolvingTerminal) return;
        resolvingTerminal = true;
        void api.getAnalysis(analysisId)
          .then((result) => {
            if (!mounted.current || activeGeneration !== generation.current) return;
            applyResult(turnId, result);
            stopRuntime();
          })
          .catch((pollError: unknown) => {
            if (!mounted.current || activeGeneration !== generation.current) return;
            setError(messageForError(pollError));
            setState("FAILED");
            stopRuntime();
          });
      },
      onTransportChange: (nextTransport) => {
        if (mounted.current && activeGeneration === generation.current) {
          setTransport(nextTransport);
        }
      },
      onError: () => undefined,
    });
  }, [api, applyResult, stopRuntime]);

  const execute = useCallback(async (
    turnId: string,
    submission: SecurityCaseSubmission,
    conversationOverride?: { id: string; version: number } | null,
  ) => {
    generation.current += 1;
    const activeGeneration = generation.current;
    stopRuntime();
    setError(null);
    setRecoveryAction(null);
    setState("RUNNING");
    setTransport("disconnected");
    setLifecycleEvents([]);
    setActiveAnalysisId(null);

    try {
      let capabilities = null;
      try {
        capabilities = await api.getCapabilities();
      } catch {
        // Capability discovery failure preserves the compatible inline path.
      }
      const useAsync = capabilities?.security_async_execution === true;
      const activeConversation = conversationOverride === undefined ? conversation : conversationOverride;
      const result = await api.createAnalysis({
        message: submission.message,
        consent,
        ...(useAsync ? { execution_mode: "async" as const } : {}),
        ...(activeConversation
          ? { conversation_id: activeConversation.id, conversation_version: activeConversation.version }
          : {}),
      }, useAsync ? { idempotencyKey: turnId } : undefined);
      if (!mounted.current || activeGeneration !== generation.current) return;
      if ("scope_decision" in result) {
        applyResult(turnId, result);
      } else {
        setTurns((current) => current.map((turn) => (
          turn.id === turnId ? { ...turn, analysisId: result.analysis_id } : turn
        )));
        setConversation({ id: result.conversation_id, version: result.conversation_version });
        setState("RUNNING");
        setActiveAnalysisId(result.analysis_id);
      }
      if (result.status === "running" || result.status === "queued") {
        monitor(turnId, result.analysis_id, activeGeneration);
      }
    } catch (submitError) {
      if (!mounted.current || activeGeneration !== generation.current) return;
      setError(messageForError(submitError));
      setRecoveryAction(submitError instanceof ApiError
        ? submitError.code === "CONVERSATION_VERSION_STALE"
          ? "reload_and_resubmit"
          : submitError.code === "NEW_CASE_REQUIRED"
            ? "start_new_case"
            : null
        : null);
      setState("FAILED");
    }
  }, [api, applyResult, consent, conversation, monitor, stopRuntime]);

  const routeFollowUp = useCallback(async (
    turnId: string,
    submission: SecurityCaseSubmission,
    settledState: SecurityCaseState,
    conversationOverride?: { id: string; version: number } | null,
  ) => {
    generation.current += 1;
    const activeGeneration = generation.current;
    stopRuntime();
    setError(null);
    setRecoveryAction(null);
    setState("CHATTING");
    setTransport("disconnected");

    try {
      const activeConversation = conversationOverride === undefined ? conversation : conversationOverride;
      const reply = await api.chat!(
        submission.message,
        activeConversation
          ? {
              conversationId: activeConversation.id,
              conversationVersion: activeConversation.version,
            }
          : undefined,
      );
      if (!mounted.current || activeGeneration !== generation.current) return;
      if (reply.route === "security_analysis") {
        await execute(turnId, submission, conversationOverride);
        return;
      }
      if (!reply.response.trim()) throw new Error("Trợ lý không trả về nội dung.");
      setTurns((current) => current.map((turn) => (
        turn.id === turnId ? { ...turn, chatResponse: reply.response } : turn
      )));
      setState(settledState);
    } catch (chatError) {
      if (!mounted.current || activeGeneration !== generation.current) return;
      setError(messageForError(chatError));
      setRecoveryAction(chatError instanceof ApiError
        && chatError.code === "CONVERSATION_VERSION_STALE"
        ? "reload_and_resubmit"
        : null);
      setState("FAILED");
    }
  }, [api, conversation, execute, stopRuntime]);

  const submit = useCallback((message: string) => {
    const submission = { message };
    const turnId = crypto.randomUUID();
    setTurns((current) => [...current, { id: turnId, idempotencyKey: turnId, result: null, ...submission }]);
    const hasCompletedTurn = turns.some((turn) => turn.result !== null);
    const shouldUseChatRouter = hasCompletedTurn
      && state !== "NEED_MORE_INFO"
      && typeof api.chat === "function";
    if (shouldUseChatRouter) {
      void routeFollowUp(turnId, submission, state);
    } else {
      void execute(turnId, submission);
    }
  }, [api.chat, execute, routeFollowUp, state, turns]);

  const retry = useCallback(() => {
    const latestTurn = turns.at(-1);
    if (!latestTurn) return;
    if (latestTurn.analysisId || latestTurn.result?.status === "queued" || latestTurn.result?.status === "running") {
      generation.current += 1;
      const activeGeneration = generation.current;
      stopRuntime();
      setError(null);
      setState(latestTurn.result ? stateFor(latestTurn.result) : "RUNNING");
      monitor(latestTurn.id, latestTurn.analysisId ?? latestTurn.result!.analysis_id, activeGeneration);
      return;
    }
    void execute(latestTurn.id, latestTurn);
  }, [execute, monitor, stopRuntime, turns]);

  const recoverLatestTurn = useCallback(async () => {
    const latestTurn = turns.at(-1);
    if (!latestTurn || !recoveryAction) return;

    if (recoveryAction === "start_new_case") {
      const newTurn: SecurityCaseTurn = {
        id: latestTurn.id,
        idempotencyKey: latestTurn.idempotencyKey,
        message: latestTurn.message,
        result: null,
      };
      setTurns([newTurn]);
      setConversation(null);
      setError(null);
      setRecoveryAction(null);
      await execute(newTurn.id, newTurn, null);
      return;
    }

    if (!conversation) return;
    try {
      const refreshed = await api.getConversation(conversation.id);
      const context = { id: refreshed.conversation_id, version: refreshed.context_version };
      setConversation(context);
      setError(null);
      setRecoveryAction(null);
      const settledResult = turns.slice(0, -1).findLast((turn) => turn.result !== null)?.result;
      if (settledResult && stateFor(settledResult) !== "NEED_MORE_INFO" && typeof api.chat === "function") {
        await routeFollowUp(latestTurn.id, latestTurn, stateFor(settledResult), context);
      } else {
        await execute(latestTurn.id, latestTurn, context);
      }
    } catch (refreshError) {
      if (!mounted.current) return;
      setError(messageForError(refreshError));
      setRecoveryAction(null);
      setState("FAILED");
    }
  }, [api, conversation, execute, recoveryAction, routeFollowUp, turns]);

  const reset = useCallback(() => {
    generation.current += 1;
    stopRuntime();
    setTurns([]);
    setConversation(null);
    setError(null);
    setRecoveryAction(null);
    setState("IDLE");
    setTransport("disconnected");
    setLifecycleEvents([]);
    setActiveAnalysisId(null);
  }, [stopRuntime]);

  const latest = turns.findLast((turn) => turn.result !== null)?.result ?? null;
  const busy = state === "CHATTING" || state === "RUNNING" || state === "PROVISIONAL_WARNING";
  const progress = selectSecurityProgress(activeAnalysisId, lifecycleEvents);

  return {
    turns,
    state,
    transport,
    error,
    recoveryAction,
    lifecycleEvents,
    progress,
    conversation,
    latest,
    busy,
    submit,
    retry,
    recoverLatestTurn,
    reset,
  };
}
