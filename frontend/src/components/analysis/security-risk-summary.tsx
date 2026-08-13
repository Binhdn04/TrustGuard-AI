import { AlertTriangle, Ban, CheckCircle2, CircleHelp, ShieldAlert } from "lucide-react";

import { cn } from "@/lib/utils";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

const ACTION_LABELS: Record<string, string> = {
  DO_NOT_OPEN_LINK: "Không mở liên kết",
  DO_NOT_SHARE_CREDENTIALS: "Không cung cấp thông tin đăng nhập",
  DO_NOT_SHARE_OTP: "Không chia sẻ mã OTP",
  DO_NOT_TRANSFER_MONEY: "Không chuyển tiền",
  VERIFY_VIA_OFFICIAL_CHANNEL: "Tự liên hệ qua kênh chính thức",
  CHANGE_PASSWORD_IF_ALREADY_SHARED: "Đổi mật khẩu nếu đã cung cấp",
  CONTACT_BANK_IF_ALREADY_PAID: "Liên hệ ngân hàng nếu đã chuyển tiền",
  REPORT_AND_BLOCK_SENDER: "Báo cáo và chặn người gửi",
  PROCEED_WITH_CAUTION: "Tiếp tục thận trọng",
};

function riskConfig(risk: SecurityScopeResponseV4["risk"]) {
  switch (risk) {
    case "SAFE": return { label: "Chưa phát hiện rủi ro", icon: CheckCircle2, style: "border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300" };
    case "LOW_RISK": return { label: "Rủi ro thấp", icon: CircleHelp, style: "border-sky-500/30 bg-sky-500/5 text-sky-700 dark:text-sky-300" };
    case "SUSPICIOUS": return { label: "Đáng ngờ", icon: AlertTriangle, style: "border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-300" };
    case "HIGH_RISK": return { label: "Rủi ro cao", icon: ShieldAlert, style: "border-orange-500/30 bg-orange-500/5 text-orange-700 dark:text-orange-300" };
    case "MALICIOUS": return { label: "Nguy hiểm", icon: Ban, style: "border-rose-500/30 bg-rose-500/5 text-rose-700 dark:text-rose-300" };
    default: return { label: "Chưa đủ bằng chứng", icon: CircleHelp, style: "border-border bg-muted/40 text-foreground" };
  }
}

export function SecurityRiskSummary({ result }: { result: SecurityScopeResponseV4 }) {
  const config = riskConfig(result.risk);
  const Icon = config.icon;
  return (
    <section aria-labelledby="risk-heading" className={cn("rounded-2xl border-2 p-5 sm:p-7", config.style)}>
      <div className="flex items-start gap-4">
        <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-background/80"><Icon className="size-6" /></span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 id="risk-heading" className="text-2xl font-bold">{config.label}</h2>
            {result.score !== null && <span className="rounded-full border border-current/20 px-3 py-1 text-sm font-bold">{result.score}/100</span>}
          </div>
          <p className="mt-2 leading-7 text-foreground">{result.explanation}</p>
          {result.threat_type && <p className="mt-2 text-xs font-semibold uppercase tracking-wide">Loại nguy cơ: {result.threat_type.replaceAll("_", " ")}</p>}
        </div>
      </div>
      {result.recommended_actions.length > 0 && (
        <div className="mt-5 border-t border-current/15 pt-4">
          <h3 className="text-sm font-bold text-foreground">Nên làm ngay</h3>
          <ul className="mt-2 grid gap-2 sm:grid-cols-2">
            {result.recommended_actions.map((action) => <li key={action} className="flex gap-2 text-sm text-foreground"><CheckCircle2 className="mt-0.5 size-4 shrink-0" />{ACTION_LABELS[action] ?? action.replaceAll("_", " ")}</li>)}
          </ul>
        </div>
      )}
    </section>
  );
}
