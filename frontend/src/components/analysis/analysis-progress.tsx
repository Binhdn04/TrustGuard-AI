"use client";

import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export type ProgressStepId = 
  | "extract" 
  | "search" 
  | "verify" 
  | "summarize" 
  | "scan_urls";

export type ProgressStepStatus = "pending" | "running" | "completed";

export interface ProgressStep {
  id: ProgressStepId;
  label: string;
  status: ProgressStepStatus;
  visible: boolean;
}

interface AnalysisProgressProps {
  steps: ProgressStep[];
}

export function AnalysisProgress({ steps }: AnalysisProgressProps) {
  const visibleSteps = steps.filter(step => step.visible);

  return (
    <div className="w-full max-w-2xl mx-auto p-6 rounded-2xl border border-border bg-card shadow-sm" aria-live="polite">
      <h3 className="text-lg font-semibold text-foreground mb-6 text-center">
        Đang phân tích dữ liệu...
      </h3>
      
      <div className="space-y-6 relative before:absolute before:inset-0 before:ml-[1.4rem] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-border before:to-transparent">
        {visibleSteps.map((step, index) => {
          const isCompleted = step.status === "completed";
          const isRunning = step.status === "running";
          const isPending = step.status === "pending";

          return (
            <div key={step.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
              
              {/* Icon marker */}
              <div 
                className={cn(
                  "flex items-center justify-center w-12 h-12 rounded-full border-4 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow-sm transition-all duration-300 z-10",
                  isCompleted ? "bg-primary border-primary/20 text-primary-foreground" :
                  isRunning ? "bg-background border-primary text-primary" :
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
                "border-border bg-background opacity-60"
              )}>
                <div className="flex items-center justify-between space-x-2 mb-1">
                  <span className={cn(
                    "font-bold text-sm",
                    isCompleted ? "text-primary" :
                    isRunning ? "text-foreground" :
                    "text-muted-foreground"
                  )}>
                    {step.label}
                  </span>
                  <span className={cn(
                    "text-[10px] font-medium px-2 py-0.5 rounded-full",
                    isCompleted ? "bg-primary/20 text-primary" :
                    isRunning ? "bg-primary text-primary-foreground animate-pulse" :
                    "bg-muted text-muted-foreground"
                  )}>
                    {isCompleted ? "Hoàn thành" : isRunning ? "Đang xử lý" : "Chờ"}
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
