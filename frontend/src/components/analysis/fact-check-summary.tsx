import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import type { FactCheckResult } from "@/types/analysis-view-model";
import { ClaimResultCard } from "./claim-result-card";

interface FactCheckSummaryProps {
  result: FactCheckResult;
}

export function FactCheckSummary({ result }: FactCheckSummaryProps) {
  const getOverallConfig = (stance: FactCheckResult["overallStance"]) => {
    switch (stance) {
      case "supports":
        return {
          title: "Được Xác Nhận",
          description: "Thông tin đã được xác minh là đúng sự thật dựa trên các nguồn đáng tin cậy.",
          color: "text-emerald-500 dark:text-emerald-400",
          bg: "bg-emerald-500/10",
          border: "border-emerald-500/30",
          icon: ShieldCheck,
        };
      case "refutes":
        return {
          title: "Sai Sự Thật",
          description: "Thông tin đã bị bác bỏ bởi các nguồn kiểm chứng uy tín.",
          color: "text-rose-500 dark:text-rose-400",
          bg: "bg-rose-500/10",
          border: "border-rose-500/30",
          icon: ShieldAlert,
        };
      case "mixed":
        return {
          title: "Đúng Một Phần / Gây Hiểu Lầm",
          description: "Nội dung chứa cả thông tin đúng và sai, hoặc thiếu ngữ cảnh quan trọng.",
          color: "text-amber-500 dark:text-amber-400",
          bg: "bg-amber-500/10",
          border: "border-amber-500/30",
          icon: AlertTriangle,
        };
      case "unrated":
      default:
        return {
          title: "Chưa Đủ Cơ Sở Kết Luận",
          description: "Không tìm thấy đủ bằng chứng để xác minh tính đúng sai của thông tin này.",
          color: "text-slate-500 dark:text-slate-400",
          bg: "bg-slate-500/10",
          border: "border-slate-500/30",
          icon: HelpCircle,
        };
    }
  };

  const config = getOverallConfig(result.overallStance);
  const Icon = config.icon;

  return (
    <div className="w-full max-w-3xl mx-auto animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className={cn("rounded-2xl border-2 overflow-hidden bg-card shadow-sm", config.border)}>
        {/* Header */}
        <div className={cn("p-6 sm:p-8 flex items-start gap-5 border-b", config.border, config.bg)}>
          <div className={cn("p-3 rounded-2xl bg-background shadow-sm shrink-0", config.color)}>
            <Icon className="w-8 h-8 sm:w-10 sm:h-10" />
          </div>
          <div className="flex-1 space-y-2">
            <h2 className={cn("text-2xl sm:text-3xl font-extrabold tracking-tight", config.color)}>
              {config.title}
            </h2>
            <p className="text-foreground/80 font-medium">
              {config.description}
            </p>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 sm:p-8 space-y-8 bg-background">
          {/* Summary Section */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
              <Info className="w-4 h-4" /> Tổng quan
            </h3>
            <p className="text-lg text-foreground leading-relaxed font-medium">
              {result.summary}
            </p>
          </div>

          {/* Claims List */}
          {result.claims.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">
                Chi tiết từng tuyên bố ({result.claims.length})
              </h3>
              <div className="space-y-4">
                {result.claims.map((claim) => (
                  <ClaimResultCard key={claim.id} claim={claim} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
