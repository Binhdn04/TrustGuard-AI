import Link from "next/link";
import { AlertTriangle, ArrowUpRight, HelpCircle, ShieldAlert, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

function presentation(item: SecurityScopeResponseV4) {
  if (item.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK") {
    return { label: "Ngoài phạm vi", Icon: HelpCircle, style: "border-border bg-muted text-foreground" };
  }
  if (item.scope_decision === "NEED_MORE_INFO") {
    return { label: "Cần thêm thông tin", Icon: HelpCircle, style: "border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200" };
  }
  if (item.risk === "SAFE" || item.risk === "LOW_RISK") {
    return { label: item.risk === "SAFE" ? "Chưa phát hiện rủi ro" : "Rủi ro thấp", Icon: ShieldCheck, style: "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200" };
  }
  if (item.risk === "HIGH_RISK" || item.risk === "MALICIOUS") {
    return { label: item.risk === "MALICIOUS" ? "Nguy hiểm" : "Rủi ro cao", Icon: ShieldAlert, style: "border-rose-500/30 bg-rose-500/10 text-rose-800 dark:text-rose-200" };
  }
  return { label: item.risk === "SUSPICIOUS" ? "Đáng ngờ" : "Chưa đủ bằng chứng", Icon: AlertTriangle, style: "border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200" };
}

function title(item: SecurityScopeResponseV4): string {
  return item.security_context?.claimed_entity
    ?? item.security_context?.potential_threat.replaceAll("_", " ")
    ?? "Security scope review";
}

export function CaseList({ items }: { items: SecurityScopeResponseV4[] }) {
  return (
    <ol aria-label="Danh sách case" className="space-y-3">
      {items.map((item) => {
        const display = presentation(item);
        return (
          <li key={item.analysis_id}>
            <article className="case-panel group p-5 transition-colors hover:border-primary/35">
              <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold">{title(item)}</p>
                    <span className="font-mono text-[10px] text-muted-foreground">{item.analysis_id.slice(0, 8)}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-sm leading-6 text-muted-foreground">
                    {item.explanation ?? item.follow_up_question ?? item.boundary_message ?? "Case chưa có mô tả kết luận."}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                    <time dateTime={item.completed_at ?? item.created_at}>{new Date(item.completed_at ?? item.created_at).toLocaleString("vi-VN")}</time>
                    <span>{item.evidence.length} evidence</span>
                    <span>{item.status}</span>
                  </div>
                  {item.security_context?.urls.map((url) => <p key={url} className="mt-1 truncate text-[11px] text-muted-foreground" title={url}>URL · {url}</p>)}
                </div>
                <div className="flex shrink-0 items-center justify-between gap-3 sm:flex-col sm:items-end">
                  <span className={cn("inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold", display.style)}>
                    <display.Icon className="size-4" aria-hidden="true" />{display.label}
                  </span>
                  <Link
                    href={`/cases/${encodeURIComponent(item.analysis_id)}`}
                    aria-label={`Mở case ${title(item)}`}
                    className="inline-flex items-center gap-1 text-xs font-bold text-primary underline-offset-4 hover:underline"
                  >
                    Mở case <ArrowUpRight className="size-3.5" aria-hidden="true" />
                  </Link>
                </div>
              </div>
            </article>
          </li>
        );
      })}
    </ol>
  );
}
