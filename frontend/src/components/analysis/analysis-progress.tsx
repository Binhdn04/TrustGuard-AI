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

export function AnalysisProgress({ phase, transport }: AnalysisProgressProps) {
  return (
    <div className="w-full max-w-xl mx-auto p-8 rounded-3xl border border-border bg-card shadow-sm flex flex-col items-center justify-center text-center" aria-live="polite">
      <div className="relative mb-6">
        <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
        <div className="relative bg-background border shadow-sm w-16 h-16 rounded-full flex items-center justify-center">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
      </div>
      
      <h3 className="text-xl font-bold text-foreground mb-2">
        {phaseLabels[phase] || "Đang xử lý"}
      </h3>
      
      <p className="text-sm text-muted-foreground">
        {transport === "polling_fallback"
          ? "Tiến trình đang được cập nhật bằng polling."
          : transport === "reconnecting"
            ? "Đang kết nối lại với luồng sự kiện."
            : "Đang kết nối với dịch vụ phân tích."}
      </p>
    </div>
  );
}
