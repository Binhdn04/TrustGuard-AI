import { BadgeCheck, Database, ExternalLink } from "lucide-react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { securityLabel } from "@/lib/presentation/security-labels";

export function EvidenceDeck({
  evidence,
  mode,
}: {
  evidence: SecurityCaseViewModel["evidence"];
  mode: SecurityPresentationMode;
}) {
  return (
    <section aria-labelledby="evidence-deck-heading">
      <div className="flex items-end justify-between gap-3">
        <div>
          <p className="micro-label">Bộ bằng chứng</p>
          <h3 id="evidence-deck-heading" className="mt-1 text-sm font-semibold">Các quan sát đã ghi nhận</h3>
        </div>
        <span className="font-mono text-xs text-muted-foreground">{evidence.length}</span>
      </div>

      {evidence.length === 0 ? (
        <div className="mt-3 rounded-xl border border-dashed border-border p-4 text-xs leading-5 text-muted-foreground">
          API chưa trả evidence cho case này.
        </div>
      ) : (
        <div className="mt-3 space-y-2">
          {evidence.map(({ evidence: item, usedInDecision }, index) => (
            <article key={item.evidence_ref} className="rounded-xl border border-border/80 bg-background/55 p-3">
              <div className="flex items-start gap-3">
                <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-[color-mix(in_srgb,var(--evidence)_12%,transparent)] text-[var(--evidence)]">
                  <Database className="size-4" aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs font-bold">E{String(index + 1).padStart(2, "0")} · {securityLabel(item.type)}</p>
                    {usedInDecision && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide text-emerald-800 dark:text-emerald-200">
                        <BadgeCheck className="size-3" />Được dùng trong kết luận
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-sm font-medium leading-5">{item.description}</p>
                  <p className="mt-1 break-all text-[11px] text-muted-foreground">{item.source}</p>
                </div>
              </div>
              {mode === "analyst" && (
                <dl className="mt-3 space-y-1 border-t border-border/70 pt-3 text-[10px] leading-4 text-muted-foreground">
                  <div className="flex justify-between gap-3"><dt>Tín hiệu</dt><dd className="text-right font-mono text-foreground">{item.signal}</dd></div>
                  <div className="flex justify-between gap-3"><dt>Đối tượng</dt><dd className="max-w-[70%] break-all text-right font-mono text-foreground">{item.target ?? "—"}</dd></div>
                  <div className="flex justify-between gap-3"><dt>Ghi nhận lúc</dt><dd className="text-right text-foreground"><time dateTime={item.observed_at}>{new Date(item.observed_at).toLocaleString("vi-VN")}</time></dd></div>
                  <div className="flex justify-between gap-3"><dt>Mức chắc chắn</dt><dd className="text-right font-mono text-foreground">{item.confidence === null ? "—" : `${Math.round(item.confidence * 100)}%`}</dd></div>
                  {item.domain_familiarity && <>
                    <div className="flex justify-between gap-3"><dt>Mức độ quen thuộc</dt><dd className="text-right text-foreground">{securityLabel(item.domain_familiarity.classification)}</dd></div>
                    <div className="flex justify-between gap-3"><dt>Domain đăng ký</dt><dd className="text-right font-mono text-foreground">{item.domain_familiarity.registrable_domain}</dd></div>
                    <div className="flex justify-between gap-3"><dt>Hạng / nhóm</dt><dd className="text-right font-mono text-foreground">{item.domain_familiarity.popularity_rank ?? "—"} / {item.domain_familiarity.popularity_bucket ?? "—"}</dd></div>
                  </>}
                  <div className="flex justify-between gap-3"><dt>Mã bằng chứng</dt><dd className="max-w-[70%] break-all text-right font-mono text-foreground">{item.evidence_ref}</dd></div>
                  {item.provenance_ref && <div className="flex justify-between gap-3"><dt>Nguồn gốc</dt><dd className="inline-flex max-w-[70%] items-start gap-1 break-all text-right font-mono text-foreground"><ExternalLink className="mt-0.5 size-3 shrink-0" />{item.provenance_ref}</dd></div>}
                </dl>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
