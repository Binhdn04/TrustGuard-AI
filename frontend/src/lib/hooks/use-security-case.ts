"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityAnalysisEventV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

export type SecurityCaseState =
  | "IDLE"
  | "RUNNING"
  | "PROVISIONAL_WARNING"
  | "OUT_OF_SCOPE_GENERAL_FACT_CHECK"
  | "NEED_MORE_INFO"
  | "COMPLETED"
  | "FAILED";

export interface SecurityCaseSubmission {
  message: string;
  externalLookup: boolean;
  officialLookup: boolean;
}

export interface SecurityCaseTurn extends SecurityCaseSubmission {
  id: string;
  analysisId?: string;
  idempotencyKey: string;
  result: SecurityScopeResponseV4 | null;
}

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
  return error instanceof Error
    ? error.message
    : "Không thể kết nối tới dịch vụ Security Triage.";
}

export function useSecurityCase(api: SecurityAnalysisApi) {
  const [turns, setTurns] = useState<SecurityCaseTurn[]>([]);
  const [state, setState] = useState<SecurityCaseState>("IDLE");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [lifecycleEvents, setLifecycleEvents] = useState<SecurityAnalysisEventV4[]>([]);
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
  }, []);

  const monitor = useCallback((turnId: string, analysisId: string, activeGeneration: number) => {
    let resolvingTerminal = false;
    subscription.current = subscribeToSecurityEvents(api, analysisId, {
      onEvents: (events) => {
        if (!mounted.current || activeGeneration !== generation.current) return;
        setLifecycleEvents((current) => [...current, ...events].sort((left, right) => left.sequence - right.sequence));
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
  ) => {
    generation.current += 1;
    const activeGeneration = generation.current;
    stopRuntime();
    setError(null);
    setState("RUNNING");
    setTransport("disconnected");
    setLifecycleEvents([]);

    try {
      let capabilities = null;
      try {
        capabilities = await api.getCapabilities();
      } catch {
        // Capability discovery failure preserves the compatible inline path.
      }
      const useAsync = capabilities?.security_async_execution === true;
      const result = await api.createAnalysis({
        message: submission.message,
        consent: {
          external_url_lookup: submission.externalLookup,
          official_source_lookup: submission.officialLookup,
        },
        execution_mode: useAsync ? "async" : "inline",
        ...(conversation
          ? { conversation_id: conversation.id, conversation_version: conversation.version }
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
      }
      if (result.status === "running" || result.status === "queued") {
        monitor(turnId, result.analysis_id, activeGeneration);
      }
    } catch (submitError) {
      if (!mounted.current || activeGeneration !== generation.current) return;
      setError(messageForError(submitError));
      setState("FAILED");
    }
  }, [api, applyResult, conversation, monitor, stopRuntime]);

  const submit = useCallback((
    message: string,
    externalLookup: boolean,
    officialLookup: boolean,
  ) => {
    const submission = { message, externalLookup, officialLookup };
    const turnId = crypto.randomUUID();
    setTurns((current) => [...current, { id: turnId, idempotencyKey: turnId, result: null, ...submission }]);
    void execute(turnId, submission);
  }, [execute]);

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

  const reset = useCallback(() => {
    generation.current += 1;
    stopRuntime();
    setTurns([]);
    setConversation(null);
    setError(null);
    setState("IDLE");
    setTransport("disconnected");
    setLifecycleEvents([]);
  }, [stopRuntime]);

  const latest = turns.at(-1)?.result ?? null;
  const busy = state === "RUNNING" || state === "PROVISIONAL_WARNING";

  return {
    turns,
    state,
    transport,
    error,
    lifecycleEvents,
    conversation,
    latest,
    busy,
    submit,
    retry,
    reset,
  };
}
