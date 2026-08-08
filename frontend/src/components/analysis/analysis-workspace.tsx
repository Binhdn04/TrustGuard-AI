"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, RefreshCw, Shield } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import { mapAnalysisResponseToViewModel } from "@/lib/mappers/analysis-v3-mapper";
import type { AnalysisEventV3, ProvisionalWarningEventV3 } from "@/types/generated/api-v3";
import type { InvestigationStep, InvestigationTool } from "@/types/analysis";
import type {
  AnalysisTransportState,
  AnalysisUiState,
  AnalysisViewModel,
} from "@/types/analysis-view-model";

import { AnalysisLimitations } from "./analysis-limitations";
import { AnalysisProgress, type ProgressStep, type ProgressStepId } from "./analysis-progress";
import { AnalysisReportForm } from "./analysis-report-form";
import { FactCheckComposer } from "./fact-check-composer";
import { FactCheckSummary } from "./fact-check-summary";
import { LinkSafetyPanel } from "./link-safety-panel";
import { LiveInvestigationPlan } from "./live-investigation-plan";
import { ProvisionalWarningBanner } from "./provisional-warning-banner";

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
  if (tool === "local_rules" && status === "completed") next = updateStep(next, "search", "running");
  if (tool === "claim_retriever" && status === "running") next = updateStep(next, "extract", "completed");
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

function upsertLiveStep(current: InvestigationStep[], next: InvestigationStep): InvestigationStep[] {
  const index = current.findIndex((step) => step.step_id === next.step_id);
  if (index < 0) return [...current, next];
  return current.map((step, itemIndex) => (itemIndex === index ? next : step));
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
  const [livePlan, setLivePlan] = useState<InvestigationStep[]>([]);
  const [provisional, setProvisional] = useState<ProvisionalWarningEventV3["payload"] | null>(null);
  const [liveLimitations, setLiveLimitations] = useState<string[]>([]);
  const [uiState, setUiState] = useState<AnalysisUiState>("idle");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const generationRef = useRef(0);

  const stopRuntime = useCallback(() => {
    if (pollTimerRef.current !== null) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = null;
  }, []);

  useEffect(() => () => {
    generationRef.current += 1;
    stopRuntime();
  }, [stopRuntime]);

  const resetWorkspace = useCallback(() => {
    generationRef.current += 1;
    stopRuntime();
    setViewModel(null);
    setError(null);
    setSteps(INITIAL_STEPS);
    setLivePlan([]);
    setProvisional(null);
    setLiveLimitations([]);
    setUiState("idle");
    setTransport("disconnected");
  }, [stopRuntime]);

  const startAnalysis = async (content: string, consentToScanUrls: boolean) => {
    generationRef.current += 1;
    const generation = generationRef.current;
    stopRuntime();
    setError(null);
    setViewModel(null);
    setLivePlan([]);
    setProvisional(null);
    setLiveLimitations([]);
    setUiState("submitting");
    setTransport("connecting");
    setSteps(initialSteps(/https?:\/\/[^\s]+/giu.test(content), consentToScanUrls));

    try {
      const api = getAnalysisApi();
      const accepted = await api.createAnalysis({
        message: content,
        consent_to_scan_urls: consentToScanUrls,
      });
      if (generation !== generationRef.current) return;
      setUiState("queued");

      const poll = async () => {
        const isCurrent = () => generation === generationRef.current;
        if (!isCurrent()) return;
        try {
          if (eventPollingAvailable) {
            try {
              const page = await api.getAnalysisEvents(accepted.analysis_id, { cursor, limit: 100 });
              if (!isCurrent()) return;
              cursor = page.next_cursor;
              setSteps((current) => page.events.reduce(applyEvent, current));
              for (const event of page.events) {
                if (event.event_type === "provisional_warning") {
                  setProvisional(event.payload);
                  setUiState("provisional");
                } else if (event.event_type === "step_transition") {
                  setLivePlan((current) => upsertLiveStep(current, event.payload));
                  setUiState((current) => (current === "provisional" ? current : "investigating"));
                } else if (event.event_type === "analysis_status" && event.payload.status === "running") {
                  setUiState((current) => (current === "provisional" ? current : "investigating"));
                } else if (event.event_type === "limitation") {
                  setLiveLimitations((current) =>
                    current.includes(event.payload.message) ? current : [...current, event.payload.message],
                  );
                }
              }
            } catch {
              if (!isCurrent()) return;
              eventPollingAvailable = false;
              setTransport("polling_fallback");
            }
          }

          const pollDetail = async (): Promise<void> => {
            if (!isCurrent()) return;
            try {
              const response = await api.getAnalysis(accepted.analysis_id);
              if (!isCurrent()) return;
              if (response.investigation_plan.length > 0) setLivePlan(response.investigation_plan);
              setSteps((current) =>
                response.investigation_plan.reduce(
                  (next, step) => applyStepTransition(next, step.tool, step.status),
                  current,
                ),
              );
              setViewModel(mapAnalysisResponseToViewModel(response, { originalContent: content, consentToScanUrls }));

              if (response.status === "completed") {
                setProvisional(null);
                setSteps((current) => current.map((step) =>
                  step.status === "skipped" || step.status === "failed"
                    ? step
                    : { ...step, status: "completed" },
                ));
                setUiState("final");
                stopRuntime();
                return;
              }
              if (response.status === "failed") {
                setProvisional(null);
                setError("Không thể hoàn tất phiên kiểm chứng này. Vui lòng thử lại.");
                setUiState("failed");
                stopRuntime();
                return;
              }

              setUiState((current) => current === "queued" ? "investigating" : current);
              if (!isCurrent()) return;
              pollTimerRef.current = setTimeout(poll, 1_500);
            } catch (pollError) {
              if (!isCurrent()) return;
              setError(errorMessage(pollError));
              setUiState("failed");
              stopRuntime();
            }
          };

          void pollDetail();
        } catch (pollError) {
          if (!isCurrent()) return;
          setError(errorMessage(pollError));
          setUiState("failed");
          stopRuntime();
        }
      };

      void poll();
    } catch (submitError) {
      if (generation !== generationRef.current) return;
      setError(errorMessage(submitError));
      setUiState("failed");
      stopRuntime();
    }
  };

  const isBusy = ["submitting", "queued", "provisional", "investigating"].includes(uiState);

  return (
    <div className="min-h-screen bg-background px-4 py-12 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-4xl space-y-8">
        <div className="space-y-4 text-center">
          <div className="inline-flex items-center justify-center rounded-full bg-primary/10 p-3">
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
            <button type="button" onClick={resetWorkspace} className="rounded-lg border border-rose-200 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-100">
              Thử lại
            </button>
          </div>
        )}

        {uiState === "idle" && !error && <FactCheckComposer onSubmit={startAnalysis} isLoading={false} />}

        {provisional && uiState !== "final" && <ProvisionalWarningBanner warning={provisional} />}

        {isBusy && (
          <>
            <AnalysisProgress
              steps={steps}
              phase={uiState as Exclude<AnalysisUiState, "idle" | "final" | "failed">}
              transport={transport}
            />
            <LiveInvestigationPlan steps={livePlan} />
            <AnalysisLimitations limitations={liveLimitations} />
          </>
        )}

        {uiState === "final" && viewModel?.factCheck && (
          <div className="space-y-6">
            <FactCheckSummary result={viewModel.factCheck} />
            <LinkSafetyPanel result={viewModel.linkSafety} />
            <AnalysisLimitations limitations={viewModel.limitations} />
            <AnalysisReportForm analysisId={viewModel.id} />
            <div className="flex justify-center pb-4 pt-4">
              <button type="button" onClick={resetWorkspace} className="flex items-center gap-2 rounded-full border border-border bg-background px-6 py-3 font-medium text-foreground shadow-sm hover:bg-muted">
                <RefreshCw className="size-4" /> Kiểm tra nội dung khác
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
