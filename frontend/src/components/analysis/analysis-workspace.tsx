"use client";

import { useEffect, useRef, useState } from "react";
import { Shield } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type {
  AnalysisCreateRequest,
  AnalysisEvent,
  AnalysisResponse,
  AnalysisStatus,
} from "@/types/analysis";

import { AnalysisProgress } from "./analysis-progress";
import { AnalysisResult } from "./analysis-result";
import { AnalysisEventTimeline } from "./analysis-event-timeline";
import { AnalyzeForm } from "./analyze-form";

const POLL_INTERVAL_MS = 500;
const MAX_POLLS = 120;

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

export function AnalysisWorkspace() {
  const [status, setStatus] = useState<AnalysisStatus | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [events, setEvents] = useState<AnalysisEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const runId = useRef(0);

  useEffect(() => () => void (runId.current += 1), []);

  async function submit(request: AnalysisCreateRequest): Promise<void> {
    const currentRun = ++runId.current;
    const api = getAnalysisApi();
    setError(null);
    setResult(null);
    setEvents([]);
    setStatus("queued");

    try {
      const accepted = await api.createAnalysis(request);
      setEvents([
        {
          analysis_id: accepted.analysis_id,
          status: accepted.status,
          step: "queued",
          occurred_at: accepted.created_at,
        },
      ]);
      for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
        await wait(POLL_INTERVAL_MS);
        if (runId.current !== currentRun) return;

        const analysis = await api.getAnalysis(accepted.analysis_id);
        setStatus(analysis.status);
        try {
          setEvents(await api.getAnalysisEvents(accepted.analysis_id));
        } catch {
          // Keep status polling usable when the optional timeline request fails.
        }
        if (analysis.status === "completed") {
          setResult(analysis);
          return;
        }
        if (analysis.status === "failed") {
          throw new Error("Quá trình phân tích thất bại. Vui lòng thử lại.");
        }
      }
      throw new Error("Quá thời gian chờ kết quả phân tích.");
    } catch (caught) {
      if (runId.current !== currentRun) return;
      setStatus(null);
      setError(
        caught instanceof Error
          ? caught.message
          : "Không thể kết nối tới dịch vụ phân tích.",
      );
    }
  }

  function reset(): void {
    runId.current += 1;
    setStatus(null);
    setResult(null);
    setEvents([]);
    setError(null);
  }

  const isAnalyzing = status === "queued" || status === "running";

  return (
    <div className="min-h-screen px-4 py-12 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-4xl space-y-12">
        <div className="space-y-4 text-center">
          <div className="mb-4 inline-flex items-center justify-center rounded-full bg-primary/10 p-3">
            <Shield className="size-8 text-primary" />
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-foreground">
            AI PROTECT <span className="text-primary">Scanner</span>
          </h1>
          <p className="mx-auto max-w-2xl text-lg text-muted-foreground">
            Hệ thống nhận diện tin giả và cảnh báo đường link lừa đảo theo thời gian thực.
          </p>
        </div>

        {!isAnalyzing && !result && (
          <div className="fade-in rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
            <AnalyzeForm onSubmit={submit} />
          </div>
        )}

        {isAnalyzing && status && (
          <div className="fade-in space-y-5">
            <AnalysisProgress status={status} />
            <AnalysisEventTimeline events={events} />
          </div>
        )}

        {error && (
          <section role="alert" className="rounded-2xl border border-rose-200 bg-rose-50 p-5 text-rose-900">
            <p className="font-semibold">Không thể hoàn tất phân tích</p>
            <p className="mt-1 text-sm">{error}</p>
            <button type="button" onClick={reset} className="mt-4 rounded-lg bg-rose-700 px-4 py-2 text-sm font-semibold text-white">
              Thử lại
            </button>
          </section>
        )}

        {result && (
          <div className="fade-in space-y-8">
            <AnalysisResult result={result} />
            <AnalysisEventTimeline events={events} />
            <div className="text-center">
              <button type="button" onClick={reset} className="rounded-full border border-border px-6 py-2 text-foreground transition-colors hover:bg-secondary">
                Kiểm tra tin nhắn khác
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
