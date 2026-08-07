import { useState } from "react";
import { Link2, ShieldCheck, AlertTriangle, ShieldAlert, ChevronDown, Activity, Globe, Link as LinkIcon, Loader2, AlertCircle, HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { LinkSafetyResult, UrlAssessment } from "@/types/analysis-view-model";

interface LinkSafetyPanelProps {
  result: LinkSafetyResult;
}

export function LinkSafetyPanel({ result }: LinkSafetyPanelProps) {
  // Auto expand if there are malicious URLs or if it's the only issue
  const hasMalicious = result.overallVerdict === "malicious" || result.overallVerdict === "suspicious";
  const [isExpanded, setIsExpanded] = useState(hasMalicious);

  if (result.status === "not_applicable") return null;

  return (
    <div className="w-full max-w-3xl mx-auto mt-6">
      <div className={cn(
        "rounded-xl border transition-all duration-300 bg-card overflow-hidden shadow-sm",
        hasMalicious ? "border-rose-500/50 shadow-rose-500/10" : "border-border hover:border-border/80"
      )}>
        {/* Header - Clickable for accordion */}
        <button 
          onClick={() => setIsExpanded(!isExpanded)}
          className={cn(
            "w-full flex items-center justify-between p-4 sm:p-5 text-left transition-colors",
            isExpanded ? "bg-muted/30" : "hover:bg-muted/50"
          )}
        >
          <div className="flex items-center gap-3 sm:gap-4">
            <div className={cn(
              "p-2 rounded-lg shrink-0",
              hasMalicious ? "bg-rose-100 text-rose-600 dark:bg-rose-950/50 dark:text-rose-400" :
              result.status === "failed" ? "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-400" :
              "bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-400"
            )}>
              <Link2 className="w-5 h-5 sm:w-6 sm:h-6" />
            </div>
            <div>
              <h3 className="text-base sm:text-lg font-bold text-foreground">
                An toàn liên kết đính kèm
              </h3>
              <p className="text-xs sm:text-sm text-muted-foreground mt-0.5">
                {result.status === "not_scanned" ? "Liên kết chưa được kiểm tra qua dịch vụ bảo mật bên ngoài." :
                 result.status === "running" ? "Đang kiểm tra mức độ an toàn của liên kết..." :
                 result.status === "failed" ? "Không thể kiểm tra an toàn liên kết." :
                 `Đã kiểm tra ${result.urls.length} liên kết.`}
              </p>
            </div>
          </div>
          <ChevronDown className={cn("w-5 h-5 text-muted-foreground transition-transform duration-300", isExpanded && "rotate-180")} />
        </button>

        {/* Content */}
        <div 
          className={cn(
            "grid transition-all duration-300", 
            isExpanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"
          )}
        >
          <div className="overflow-hidden">
            <div className="p-4 sm:p-5 border-t border-border bg-background">
              
              {/* Not Scanned State */}
              {result.status === "not_scanned" && (
                <div className="flex items-center gap-3 p-4 rounded-lg border border-dashed border-border bg-muted/30 text-muted-foreground">
                  <ShieldCheck className="w-5 h-5 shrink-0" />
                  <span className="text-sm">
                    Bạn đã không cấp quyền kiểm tra URL qua dịch vụ bên ngoài. Nội dung chỉ được phân tích fact-check.
                  </span>
                </div>
              )}

              {/* Running State */}
              {result.status === "running" && (
                <div className="flex flex-col items-center justify-center p-8 text-muted-foreground space-y-4">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                  <span className="text-sm font-medium">Đang quét URL...</span>
                </div>
              )}

              {/* Failed State */}
              {result.status === "failed" && (
                <div className="flex items-center gap-3 p-4 rounded-lg border border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-900/50 dark:bg-rose-950/50 dark:text-rose-400">
                  <AlertCircle className="w-5 h-5 shrink-0" />
                  <span className="text-sm font-medium">
                    Có lỗi xảy ra khi quét liên kết. {result.limitations.join(" ")}
                  </span>
                </div>
              )}

              {/* Completed State */}
              {result.status === "completed" && result.urls.length > 0 && (
                <div className="space-y-4">
                  {result.urls.map((url, idx) => (
                    <UrlAssessmentCard key={idx} assessment={url} />
                  ))}
                  
                  {result.limitations.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-border/50">
                      <h5 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Giới hạn</h5>
                      <ul className="list-disc list-inside text-xs text-muted-foreground space-y-1">
                        {result.limitations.map((lim, i) => <li key={i}>{lim}</li>)}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Sub-component for individual URL assessment
function UrlAssessmentCard({ assessment }: { assessment: UrlAssessment }) {
  const getVerdictConfig = (verdict: UrlAssessment["verdict"]) => {
    switch (verdict) {
      case "safe": return { color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-50 dark:bg-emerald-950/30", border: "border-emerald-200 dark:border-emerald-800", icon: ShieldCheck, label: "An toàn" };
      case "suspicious": return { color: "text-amber-600 dark:text-amber-400", bg: "bg-amber-50 dark:bg-amber-950/30", border: "border-amber-200 dark:border-amber-800", icon: AlertTriangle, label: "Đáng ngờ" };
      case "malicious": return { color: "text-rose-600 dark:text-rose-400", bg: "bg-rose-50 dark:bg-rose-950/30", border: "border-rose-200 dark:border-rose-800", icon: ShieldAlert, label: "Nguy hiểm" };
      case "inconclusive":
      default: return { color: "text-muted-foreground", bg: "bg-muted/40", border: "border-border", icon: HelpCircle, label: "Chưa rõ" };
    }
  };

  const config = getVerdictConfig(assessment.verdict);
  const Icon = config.icon;

  return (
    <div className={cn("p-4 rounded-xl border transition-all", config.border, config.bg)}>
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        
        {/* Main URL Info */}
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-2 mb-1">
            <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase", config.color, "bg-background shadow-sm border border-border/50")}>
              <Icon className="w-3 h-3 mr-1" />
              {config.label}
            </span>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Activity className="w-3 h-3" /> {assessment.provider || "Unknown Scanner"}
            </span>
          </div>
          
          <p className="text-sm font-medium text-foreground truncate flex items-center gap-1.5" title={assessment.url}>
            <LinkIcon className="w-4 h-4 text-muted-foreground shrink-0" />
            {assessment.url}
          </p>

          {/* Signals */}
          {assessment.signals.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {assessment.signals.map((signal, i) => (
                <span key={i} className="inline-flex items-center px-2 py-1 rounded bg-background border border-border text-[10px] text-muted-foreground">
                  {signal}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Metadata Sidebar */}
        <div className="sm:w-48 shrink-0 flex flex-col gap-2 p-3 rounded-lg bg-background/50 border border-border/50">
          {assessment.domainRegisteredAt && (
            <div className="flex items-start gap-2 text-xs">
              <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
              <div>
                <span className="block text-muted-foreground">Đăng ký domain:</span>
                <span className="font-medium text-foreground">{new Date(assessment.domainRegisteredAt).toLocaleDateString("vi-VN")}</span>
              </div>
            </div>
          )}
          {assessment.redirects.length > 0 && (
            <div className="flex items-start gap-2 text-xs">
              <Link2 className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
              <div>
                <span className="block text-muted-foreground">Chuyển hướng:</span>
                <span className="font-medium text-foreground">{assessment.redirects.length} lần</span>
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
