"use client";

import { useState, useEffect, useRef } from "react";
import { Shield, AlertCircle, RefreshCw } from "lucide-react";
import { FactCheckComposer } from "./fact-check-composer";
import { AnalysisProgress, type ProgressStep } from "./analysis-progress";
import { FactCheckSummary } from "./fact-check-summary";
import { LinkSafetyPanel } from "./link-safety-panel";
import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { AnalysisViewModel } from "@/types/analysis";

const INITIAL_STEPS: ProgressStep[] = [
  { id: "extract", label: "Đang xác định các phát biểu cần kiểm chứng", status: "pending", visible: true },
  { id: "search", label: "Đang tìm nguồn fact-check", status: "pending", visible: true },
  { id: "verify", label: "Đang đối chiếu bằng chứng", status: "pending", visible: true },
  { id: "summarize", label: "Đang tổng hợp kết luận", status: "pending", visible: true },
  { id: "scan_urls", label: "Đang kiểm tra liên kết đính kèm", status: "pending", visible: false },
];

export function AnalysisWorkspace() {
  const [viewModel, setViewModel] = useState<AnalysisViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [steps, setSteps] = useState<ProgressStep[]>(INITIAL_STEPS);
  
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  const [activeAnalysisId, setActiveAnalysisId] = useState<string | null>(null);

  const clearPolling = () => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  // Cleanup polling on unmount
  useEffect(() => clearPolling, []);

  const simulateProgress = (hasConsent: boolean, hasUrl: boolean) => {
    // Show URL scan step if needed
    setSteps(INITIAL_STEPS.map(s => {
      if (s.id === "scan_urls") {
        return { ...s, visible: hasUrl && hasConsent };
      }
      return s;
    }));

    // Simulating the progress sequence for visual effect
    const sequence = [
      { id: "extract", delay: 0 },
      { id: "search", delay: 1000 },
      { id: "verify", delay: 2000 },
      { id: "summarize", delay: 3500 },
    ];
    
    if (hasUrl && hasConsent) {
      sequence.push({ id: "scan_urls", delay: 4500 });
    }

    sequence.forEach(({ id, delay }, i) => {
      setTimeout(() => {
        setSteps(prev => prev.map(s => {
          if (s.id === id) return { ...s, status: "running" };
          const previousId = i > 0 ? sequence[i - 1].id : null;
          if (previousId && s.id === previousId) return { ...s, status: "completed" };
          return s;
        }));
      }, delay);
    });
  };

  const startAnalysis = async (content: string, consentToScanUrls: boolean) => {
    setError(null);
    setViewModel(null);
    clearPolling();
    
    const hasUrl = /https?:\/\/[^\s]+/giu.test(content);
    simulateProgress(consentToScanUrls, hasUrl);

    try {
      const api = getAnalysisApi();
      const accepted = await api.createAnalysis({ message: content, consent_to_scan_urls: consentToScanUrls });
      setActiveAnalysisId(accepted.analysis_id);
      pollAnalysis(accepted.analysis_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Đã xảy ra lỗi khi kết nối với máy chủ.");
    }
  };

  const pollAnalysis = async (id: string) => {
    try {
      const api = getAnalysisApi();
      const result = await api.getAnalysis(id);
      
      if (result.status === "completed" || result.status === "failed") {
        // Complete all steps if finished
        setSteps(prev => prev.map(s => ({ ...s, status: "completed" })));
        setViewModel(result);
        setActiveAnalysisId(null);
      } else {
        setViewModel(result); // Update partial state (running)
        pollTimerRef.current = setTimeout(() => pollAnalysis(id), 1500);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Mất kết nối khi đang lấy kết quả.");
      setActiveAnalysisId(null);
    }
  };

  const resetWorkspace = () => {
    setViewModel(null);
    setError(null);
    setSteps(INITIAL_STEPS);
    clearPolling();
    setActiveAnalysisId(null);
  };

  const isRunning = activeAnalysisId !== null || (viewModel && viewModel.status === "running");

  return (
    <div className="min-h-screen py-12 px-4 sm:px-6 lg:px-8 bg-background">
      <div className="max-w-4xl mx-auto space-y-12">
        
        {/* Header Section */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center p-3 bg-primary/10 rounded-full mb-4">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-foreground">
            Fact-Check <span className="text-primary">AI</span>
          </h1>
        </div>

        {/* Error State */}
        {error && (
          <div className="max-w-2xl mx-auto p-4 rounded-xl border border-rose-200 bg-rose-50 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-bold text-rose-800">Lỗi phân tích</h3>
              <p className="text-sm text-rose-700 mt-1">{error}</p>
            </div>
            <button 
              onClick={resetWorkspace}
              className="text-sm px-3 py-1.5 rounded-lg border border-rose-200 text-rose-700 hover:bg-rose-100 font-medium"
            >
              Thử lại
            </button>
          </div>
        )}

        {/* Input Phase */}
        {!isRunning && !viewModel?.factCheck && !error && (
          <FactCheckComposer onSubmit={startAnalysis} />
        )}

        {/* Progress Phase */}
        {isRunning && (
          <AnalysisProgress steps={steps} />
        )}

        {/* Result Phase */}
        {viewModel?.factCheck && !isRunning && (
          <div className="space-y-6">
            <FactCheckSummary result={viewModel.factCheck} />
            
            <LinkSafetyPanel result={viewModel.linkSafety} />

            <div className="flex justify-center pt-8 pb-4">
              <button
                onClick={resetWorkspace}
                className="flex items-center gap-2 px-6 py-3 rounded-full border border-border bg-background text-foreground hover:bg-muted font-medium transition-colors shadow-sm"
              >
                <RefreshCw className="w-4 h-4" />
                Kiểm tra tin nhắn khác
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
