"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, RefreshCw, Shield } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import {
  subscribeToAnalysisEvents,
  type AnalysisEventSubscription,
} from "@/lib/api/analysis-event-stream";
import { mapAnalysisResponseToViewModel } from "@/lib/mappers/analysis-v3-mapper";
import type { AnalysisEventV3, ProvisionalWarningEventV3 } from "@/types/generated/api-v3";
import type { InvestigationStep } from "@/types/analysis";
import type {
  AnalysisTransportState,
  AnalysisUiState,
  AnalysisViewModel,
} from "@/types/analysis-view-model";

import { AnalysisLimitations } from "./analysis-limitations";
import { AnalysisProgress } from "./analysis-progress";
import { AnalysisReportForm } from "./analysis-report-form";
import { FactCheckComposer } from "./fact-check-composer";
import { FactCheckSummary } from "./fact-check-summary";
import { LinkSafetyPanel } from "./link-safety-panel";
import { LiveInvestigationPlan } from "./live-investigation-plan";
import { ProvisionalWarningBanner } from "./provisional-warning-banner";

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
  const [livePlan, setLivePlan] = useState<InvestigationStep[]>([]);
  const [provisional, setProvisional] = useState<ProvisionalWarningEventV3["payload"] | null>(null);
  const [liveLimitations, setLiveLimitations] = useState<string[]>([]);
  const [uiState, setUiState] = useState<AnalysisUiState>("idle");
  const [transport, setTransport] = useState<AnalysisTransportState>("disconnected");
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const eventSubscriptionRef = useRef<AnalysisEventSubscription | null>(null);
  const generationRef = useRef(0);

  const stopRuntime = useCallback(() => {
    if (pollTimerRef.current !== null) clearTimeout(pollTimerRef.current);
    pollTimerRef.current = null;
    eventSubscriptionRef.current?.stop();
    eventSubscriptionRef.current = null;
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

    try {
      const api = getAnalysisApi();
      const accepted = await api.createAnalysis({
        message: content,
        consent_to_scan_urls: consentToScanUrls,
      });
      if (generation !== generationRef.current) return;
      setUiState("queued");

      const handleEvents = (events: AnalysisEventV3[]) => {
        if (generation !== generationRef.current) return;
        for (const event of events) {
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
      };

      eventSubscriptionRef.current = subscribeToAnalysisEvents(
        api,
        accepted.analysis_id,
        {
          onEvents: handleEvents,
          onTransportChange: (nextTransport) => {
            if (generation === generationRef.current) setTransport(nextTransport);
          },
        },
      );

      const pollDetail = async () => {
        const isCurrent = () => generation === generationRef.current;
        if (!isCurrent()) return;
        try {
          const response = await api.getAnalysis(accepted.analysis_id);
          if (!isCurrent()) return;
          if (response.investigation_plan.length > 0) setLivePlan(response.investigation_plan);
          setViewModel(mapAnalysisResponseToViewModel(response, { originalContent: content, consentToScanUrls }));

          if (response.status === "completed") {
            setProvisional(null);
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
          pollTimerRef.current = setTimeout(() => void pollDetail(), 1_500);
        } catch (pollError) {
          if (!isCurrent()) return;
          setError(errorMessage(pollError));
          setUiState("failed");
          stopRuntime();
        }
      };

      void pollDetail();
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
