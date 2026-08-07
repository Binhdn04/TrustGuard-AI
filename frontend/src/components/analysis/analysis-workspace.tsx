"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, RefreshCw, Shield } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import { mapAnalysisResponseToViewModel } from "@/lib/mappers/analysis-v3-mapper";
import type { AnalysisEventV3 } from "@/types/generated/api-v3";
import type { InvestigationStep, InvestigationTool } from "@/types/analysis";
import type {
  AnalysisTransportState,
  AnalysisUiState,
  AnalysisViewModel,
} from "@/types/analysis-view-model";

import { AnalysisProgress, type ProgressStep, type ProgressStepId } from "./analysis-progress";
import { FactCheckComposer } from "./fact-check-composer";
import { FactCheckSummary } from "./fact-check-summary";
import { LinkSafetyPanel } from "./link-safety-panel";

const INITIAL_STEPS: ProgressStep[] = [
  { id: "extract", label: "Xác định các phát biểu cần kiểm chứng", status: "pending", visible: true },
  { id: "search", label: "Tìm nguồn fact-check", status: "pending", visible: true },
  { id: "verify", label: "Đối chiếu bằng chứng", status: "pending", visible: true },
  { id: "summarize", label: "Tổng hợp kết luận", status: "pending", visible: true },
  { id: "scan_urls", label: "Kiểm tra liên kết đính kèm", status: "pending", visible: false },
];

const TOOL_STEP: Partial<Record<InvestigationTool, ProgressStepId>> = {
  local_rules: "extract",
  claim_retriever: "search",
  url_scanner: "scan_urls",
  redirect_resolver: "scan_urls",
  domain_intelligence: "scan_urls",
  blacklist_lookup: "scan_urls",
};

function initialSteps(hasUrl: boolean, consent: boolean): ProgressStep[] {
  return INITIAL_STEPS.map((step) => ({
    ...step,
    visible: step.id !== "scan_urls" || (hasUrl && consent),
  }));
}

function updateStep(
  steps: ProgressStep[],
  id: ProgressStepId,
  status: ProgressStep["status"],
): ProgressStep[] {
  return steps.map((step) => (step.id === id ? { ...step, status } : step));
}

function applyStepTransition(
  steps: ProgressStep[],
  tool: InvestigationTool,
  status: ProgressStep["status"],
): ProgressStep[] {
  const id = TOOL_STEP[tool];
  if (!id) return steps;
  let next = updateStep(steps, id, status);
  if (tool === "local_rules" && status === "completed") {
    next = updateStep(next, "search", "running");
  }
  if (tool === "claim_retriever" && status === "running") {
    next = updateStep(next, "extract", "completed");
  }
  if (tool === "claim_retriever" && status === "completed") {
    next = updateStep(next, "verify", "completed");
    next = updateStep(next, "summarize", "running");
  }
  return next;
}

function applyEvent(steps: ProgressStep[], event: AnalysisEventV3): ProgressStep[] {
  if (event.event_type === "analysis_status" && event.payload.status === "running") {
    return updateStep(steps, "extract", "running");
  }
  if (event.event_type === "step_transition") {
    return applyStepTransition(steps, event.payload.tool, event.payload.status);
  }
  if (event.event_type === "final_result") {
    return steps.map((step) =>
      step.status === "skipped" || step.status === "failed"
        ? step
        : { ...step, status: "completed" },
    );
  }
  return steps;
}

function mergePlan(steps: ProgressStep[], plan: InvestigationStep[]): ProgressStep[] {
  return plan.reduce(
    (current, step) => applyStepTransition(current, step.tool, step.status),
    steps,
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "Đã xảy ra lỗi khi kết nối với dịch vụ phân tích.";
}

export function AnalysisWorkspace() {
  const [viewModel, setViewModel] = useState<AnalysisViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [steps, setSteps] = useState<ProgressStep[]>(INITIAL_STEPS);
  const [uiState, setUiState] = useState<AnalysisUiState>("idle");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const generationRef = useRef(0);

  const clearPolling = useCallback(() => {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      generationRef.current += 1;
      clearPolling();
    };
  }, [clearPolling]);

  const resetWorkspace = useCallback(() => {
    generationRef.current += 1;
    clearPolling();
    setViewModel(null);
    setError(null);
    setSteps(INITIAL_STEPS);
    setUiState("idle");
    setTransport("disconnected");
  }, [clearPolling]);

  const startAnalysis = async (content: string, consentToScanUrls: boolean) => {
    generationRef.current += 1;
    const generation = generationRef.current;
    clearPolling();
    setError(null);
    setViewModel(null);
    setUiState("submitting");
    setTransport("connecting");

    const hasUrl = /https?:\/\/[^\s]+/giu.test(content);
    setSteps(initialSteps(hasUrl, consentToScanUrls));

    try {
      const api = getAnalysisApi();
      const accepted = await api.createAnalysis({
        message: content,
        consent_to_scan_urls: consentToScanUrls,
      });
      if (generation !== generationRef.current) return;

      setUiState("queued");
      setTransport("polling_fallback");
      let cursor: string | null = null;
      let eventPollingAvailable = true;

      const poll = async () => {
        if (generation !== generationRef.current) return;
        try {
          if (eventPollingAvailable) {
            try {
              const page = await api.getAnalysisEvents(accepted.analysis_id, { cursor, limit: 100 });
              cursor = page.next_cursor;
              setSteps((current) => page.events.reduce(applyEvent, current));
              if (page.events.some((event) => event.event_type === "provisional_warning")) {
                setUiState("provisional");
              } else if (
                page.events.some(
                  (event) =>
                    event.event_type === "step_transition" ||
                    (event.event_type === "analysis_status" && event.payload.status === "running"),
                )
              ) {
                setUiState("investigating");
              }
            } catch {
              eventPollingAvailable = false;
              setTransport("polling_fallback");
            }
          }

          const response = await api.getAnalysis(accepted.analysis_id);
          if (generation !== generationRef.current) return;
          setSteps((current) => mergePlan(current, response.investigation_plan));
          setViewModel(
            mapAnalysisResponseToViewModel(response, {
              originalContent: content,
              consentToScanUrls,
            }),
          );

          if (response.status === "completed") {
            setSteps((current) =>
              current.map((step) =>
                step.status === "skipped" || step.status === "failed"
                  ? step
                  : { ...step, status: "completed" },
              ),
            );
            setUiState("final");
            setTransport("disconnected");
            clearPolling();
            return;
          }
          if (response.status === "failed") {
            setError("Không thể hoàn tất phiên kiểm chứng này. Vui lòng thử lại.");
            setUiState("failed");
            setTransport("disconnected");
            clearPolling();
            return;
          }

          if (uiState === "queued") setUiState("investigating");
          pollTimerRef.current = setTimeout(poll, 1_500);
        } catch (pollError) {
          if (generation !== generationRef.current) return;
          setError(errorMessage(pollError));
          setUiState("failed");
          setTransport("disconnected");
          clearPolling();
        }
      };

      void poll();
    } catch (submitError) {
      if (generation !== generationRef.current) return;
      setError(errorMessage(submitError));
      setUiState("failed");
      setTransport("disconnected");
    }
  };

  const isBusy = ["submitting", "queued", "provisional", "investigating"].includes(uiState);

  return (
    <div className="min-h-screen bg-background px-4 py-12 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-4xl space-y-12">
        <div className="space-y-4 text-center">
          <div className="mb-4 inline-flex items-center justify-center rounded-full bg-primary/10 p-3">
            <Shield className="size-8 text-primary" />
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-foreground">
            Fact-Check <span className="text-primary">AI</span>
          </h1>
        </div>

        {error && (
          <div role="alert" className="mx-auto flex max-w-2xl items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4">
            <AlertCircle className="mt-0.5 size-5 shrink-0 text-rose-600" />
            <div className="flex-1">
              <h2 className="text-sm font-bold text-rose-800">Lỗi phân tích</h2>
              <p className="mt-1 text-sm text-rose-700">{error}</p>
            </div>
            <button
              type="button"
              onClick={resetWorkspace}
              className="rounded-lg border border-rose-200 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-100"
            >
              Thử lại
            </button>
          </div>
        )}

        {uiState === "idle" && !error && (
          <FactCheckComposer onSubmit={startAnalysis} isLoading={false} />
        )}

        {isBusy && (
          <AnalysisProgress
            steps={steps}
            phase={uiState as Exclude<AnalysisUiState, "idle" | "final" | "failed">}
            transport={transport}
          />
        )}

        {uiState === "final" && viewModel?.factCheck && (
          <div className="space-y-6">
            <FactCheckSummary result={viewModel.factCheck} />
            <LinkSafetyPanel result={viewModel.linkSafety} />
            <div className="flex justify-center pb-4 pt-8">
              <button
                type="button"
                onClick={resetWorkspace}
                className="flex items-center gap-2 rounded-full border border-border bg-background px-6 py-3 font-medium text-foreground shadow-sm transition-colors hover:bg-muted"
              >
                <RefreshCw className="size-4" />
                Kiểm tra nội dung khác
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
