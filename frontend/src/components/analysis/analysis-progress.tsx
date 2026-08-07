"use client";

import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type {
  AnalysisTransportState,
  AnalysisUiState,
} from "@/types/analysis-view-model";

export type ProgressStepId = 
  | "extract" 
  | "search" 
  | "verify" 
  | "summarize" 
  | "scan_urls";

export type ProgressStepStatus =
  | "pending"
  | "running"
  | "completed"
  | "skipped"
  | "failed";

export interface ProgressStep {
  id: ProgressStepId;
  label: string;
  status: ProgressStepStatus;
  visible: boolean;
}

interface AnalysisProgressProps {
  steps: ProgressStep[];
  phase: Exclude<AnalysisUiState, "idle" | "final" | "failed">;
  transport: AnalysisTransportState;
}

const phaseLabels: Record<AnalysisProgressProps["phase"], string> = {
  submitting: "Đang gửi yêu cầu phân tích",
  queued: "Yêu cầu đang chờ xử lý",
  provisional: "Đã có cảnh báo sơ bộ, hệ thống vẫn đang kiểm chứng",
  investigating: "Đang kiểm chứng thông tin",
};

const statusLabels: Record<ProgressStepStatus, string> = {
  pending: "Chờ",
  running: "Đang xử lý",
  completed: "Hoàn thành",
  skipped: "Bỏ qua",
  failed: "Không hoàn tất",
};

export function AnalysisProgress({ steps, phase, transport }: AnalysisProgressProps) {
  const visibleSteps = steps.filter(step => step.visible);

  return (
    <div className="w-full max-w-2xl mx-auto p-6 rounded-2xl border border-border bg-card shadow-sm" aria-live="polite">
      <h3 className="text-lg font-semibold text-foreground mb-6 text-center">
        {phaseLabels[phase]}
      </h3>
      <p className="-mt-4 mb-6 text-center text-xs text-muted-foreground">
        {transport === "polling_fallback"
          ? "Tiến trình đang được cập nhật bằng polling."
          : transport === "reconnecting"
            ? "Đang kết nối lại với luồng sự kiện."
            : "Đang kết nối với dịch vụ phân tích."}
      </p>
      
      <div className="space-y-6 relative before:absolute before:inset-0 before:ml-[1.4rem] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-border before:to-transparent">
        {visibleSteps.map((step) => {
          const isCompleted = step.status === "completed";
          const isRunning = step.status === "running";
          const isFailed = step.status === "failed";

          return (
            <div key={step.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
              
              {/* Icon marker */}
              <div 
                className={cn(
                  "flex items-center justify-center w-12 h-12 rounded-full border-4 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow-sm transition-all duration-300 z-10",
                  isCompleted ? "bg-primary border-primary/20 text-primary-foreground" :
                  isRunning ? "bg-background border-primary text-primary" :
                  isFailed ? "bg-rose-100 border-rose-200 text-rose-700" :
                  "bg-muted border-background text-muted-foreground"
                )}
              >
                {isCompleted ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : isRunning ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Circle className="w-3 h-3 fill-current" />
                )}
              </div>

              {/* Text content */}
              <div className={cn(
                "w-[calc(100%-4rem)] md:w-[calc(50%-3rem)] p-4 rounded-xl border transition-all duration-300",
                isCompleted ? "border-primary/20 bg-primary/5" :
                isRunning ? "border-primary bg-background shadow-md scale-[1.02]" :
                isFailed ? "border-rose-200 bg-rose-50/70" :
                "border-border bg-background opacity-60"
              )}>
                <div className="flex items-center justify-between space-x-2 mb-1">
                  <span className={cn(
                    "font-bold text-sm",
                    isCompleted ? "text-primary" :
                    isRunning ? "text-foreground" :
                    isFailed ? "text-rose-700" :
                    "text-muted-foreground"
                  )}>
                    {step.label}
                  </span>
                  <span className={cn(
                    "text-[10px] font-medium px-2 py-0.5 rounded-full",
                    isCompleted ? "bg-primary/20 text-primary" :
                    isRunning ? "bg-primary text-primary-foreground animate-pulse" :
                    isFailed ? "bg-rose-100 text-rose-700" :
                    "bg-muted text-muted-foreground"
                  )}>
                    {statusLabels[step.status]}
                  </span>
                </div>
              </div>

            </div>
          );
        })}
      </div>
    </div>
  );
}
