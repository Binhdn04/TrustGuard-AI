import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle, ShieldAlert, AlertCircle, Info, ExternalLink } from "lucide-react";
import { motion } from "framer-motion";

export type RiskLevel = "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "INCONCLUSIVE";

interface VerdictCardProps {
  score: number;
  level: RiskLevel;
  reason: string;
  recommendation: string;
  limitations?: string[];
}

export function VerdictCard({ score, level, reason, recommendation, limitations }: VerdictCardProps) {
  const levelConfig = {
    SAFE: {
      color: "text-emerald-500",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/30",
      icon: CheckCircle,
      label: "An Toàn",
    },
    SUSPICIOUS: {
      color: "text-amber-500",
      bg: "bg-amber-500/10",
      border: "border-amber-500/30",
      icon: AlertTriangle,
      label: "Đáng Ngờ",
    },
    MALICIOUS: {
      color: "text-rose-500",
      bg: "bg-rose-500/10",
      border: "border-rose-500/30",
      icon: ShieldAlert,
      label: "Độc Hại",
    },
    INCONCLUSIVE: {
      color: "text-slate-400",
      bg: "bg-slate-400/10",
      border: "border-slate-400/30",
      icon: AlertCircle,
      label: "Không Thể Kết Luận",
    },
  };

  const config = levelConfig[level];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.5, type: "spring" }}
      className="w-full max-w-3xl mx-auto"
    >
      <Card className={cn("overflow-hidden border-t-4", config.border)}>
        <CardHeader className={cn("pb-4", config.bg)}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Icon className={cn("w-8 h-8", config.color)} />
              <div>
                <CardTitle className="text-2xl font-bold">{config.label}</CardTitle>
                <CardDescription className="text-foreground/80 mt-1">
                  Điểm rủi ro: <span className="font-semibold">{score}/100</span>
                </CardDescription>
              </div>
            </div>
            
            {/* Risk Gauge - Simple implementation */}
            <div className="relative w-16 h-16 rounded-full border-4 border-muted flex items-center justify-center">
              <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle
                  cx="50" cy="50" r="46"
                  fill="transparent"
                  stroke="currentColor"
                  strokeWidth="8"
                  strokeDasharray={`${(score / 100) * 289} 289`}
                  className={config.color}
                />
              </svg>
              <span className="text-lg font-bold">{score}</span>
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="pt-6 space-y-6">
          <div>
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2">Kết Luận</h4>
            <p className="text-foreground text-lg leading-relaxed">{reason}</p>
          </div>
          
          <div className="bg-secondary/50 rounded-lg p-4 border border-border">
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center">
              <Info className="w-4 h-4 mr-2" /> Đề Xuất Hành Động
            </h4>
            <p className="text-foreground font-medium">{recommendation}</p>
          </div>

          {limitations && limitations.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-muted-foreground mb-2">Hạn chế về dữ liệu:</h4>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground/80">
                {limitations.map((limit, i) => (
                  <li key={i}>{limit}</li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
        
        <CardFooter className="bg-muted/30 py-4 border-t border-border flex justify-between">
          <button className="text-sm text-muted-foreground hover:text-foreground flex items-center transition-colors">
            Xem chi tiết bằng chứng <ExternalLink className="w-4 h-4 ml-1" />
          </button>
          <button className="text-sm text-muted-foreground hover:text-foreground underline transition-colors">
            Báo cáo sai kết quả
          </button>
        </CardFooter>
      </Card>
    </motion.div>
  );
}
