import { ExternalLink, ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle, FileText } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ClaimResult } from "@/types/analysis";

interface ClaimResultCardProps {
  claim: ClaimResult;
}

export function ClaimResultCard({ claim }: ClaimResultCardProps) {
  const getStanceConfig = (stance: ClaimResult["stance"]) => {
    switch (stance) {
      case "supports":
        return {
          label: "Được nguồn xác nhận",
          color: "text-emerald-600 dark:text-emerald-400",
          bg: "bg-emerald-50 dark:bg-emerald-950/30",
          border: "border-emerald-200 dark:border-emerald-800",
          icon: ShieldCheck,
        };
      case "refutes":
        return {
          label: "Bị nguồn bác bỏ",
          color: "text-rose-600 dark:text-rose-400",
          bg: "bg-rose-50 dark:bg-rose-950/30",
          border: "border-rose-200 dark:border-rose-800",
          icon: ShieldAlert,
        };
      case "mixed":
        return {
          label: "Đúng một phần / Thiếu ngữ cảnh",
          color: "text-amber-600 dark:text-amber-400",
          bg: "bg-amber-50 dark:bg-amber-950/30",
          border: "border-amber-200 dark:border-amber-800",
          icon: AlertTriangle,
        };
      case "unrated":
      default:
        return {
          label: "Chưa đủ bằng chứng",
          color: "text-muted-foreground",
          bg: "bg-muted/40",
          border: "border-border",
          icon: HelpCircle,
        };
    }
  };

  const config = getStanceConfig(claim.stance);
  const Icon = config.icon;

  return (
    <div className={cn("p-5 rounded-2xl border transition-colors", config.border, config.bg)}>
      <div className="flex items-start gap-4">
        <div className={cn("p-2 rounded-xl bg-background shadow-sm shrink-0", config.color)}>
          <Icon className="w-6 h-6" />
        </div>
        <div className="flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-background shadow-sm border border-border", config.color)}>
              {config.label}
            </span>
            {claim.confidence !== null && (
              <span className="text-xs font-medium text-muted-foreground">
                Độ tin cậy: {Math.round(claim.confidence * 100)}%
              </span>
            )}
          </div>
          
          <h4 className="text-lg font-semibold text-foreground leading-snug">
            &quot;{claim.text}&quot;
          </h4>
          
          <p className="text-sm text-foreground/80 leading-relaxed">
            {claim.explanation}
          </p>

          {/* Sources */}
          {claim.sources.length > 0 && (
            <div className="mt-4 pt-4 border-t border-border/50">
              <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                Nguồn & Bằng chứng ({claim.sources.length})
              </h5>
              <div className="space-y-2.5">
                {claim.sources.map((source) => (
                  <a 
                    key={source.id} 
                    href={source.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="group block p-3 rounded-xl bg-background border border-border hover:border-primary/30 hover:shadow-sm transition-all"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-1.5 mb-1">
                          <span className="text-xs font-medium text-primary line-clamp-1">{source.publisher}</span>
                          {source.official && (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-primary/10 text-primary uppercase">
                              Chính thức
                            </span>
                          )}
                        </div>
                        <p className="text-sm font-medium text-foreground group-hover:text-primary transition-colors line-clamp-2">
                          {source.title}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Kết luận: {source.finding}
                        </p>
                      </div>
                      <ExternalLink className="w-4 h-4 text-muted-foreground group-hover:text-primary shrink-0 transition-colors" />
                    </div>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
