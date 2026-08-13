import { BadgeCheck, Database, ExternalLink } from "lucide-react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";

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
          <p className="micro-label">Evidence deck</p>
          <h3 id="evidence-deck-heading" className="mt-1 text-sm font-semibold">Recorded observations</h3>
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
                    <p className="text-xs font-bold">E{String(index + 1).padStart(2, "0")} · {item.type.replaceAll("_", " ")}</p>
                    {usedInDecision && (
                      <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide text-emerald-800 dark:text-emerald-200">
                        <BadgeCheck className="size-3" />Used in decision
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-sm font-medium leading-5">{item.description}</p>
                  <p className="mt-1 break-all text-[11px] text-muted-foreground">{item.source}</p>
                </div>
              </div>
              {mode === "analyst" && (
                <dl className="mt-3 space-y-1 border-t border-border/70 pt-3 text-[10px] leading-4 text-muted-foreground">
                  <div className="flex justify-between gap-3"><dt>Signal</dt><dd className="text-right font-mono text-foreground">{item.signal}</dd></div>
                  <div className="flex justify-between gap-3"><dt>Target</dt><dd className="max-w-[70%] break-all text-right font-mono text-foreground">{item.target ?? "—"}</dd></div>
                  <div className="flex justify-between gap-3"><dt>Observed</dt><dd className="text-right text-foreground"><time dateTime={item.observed_at}>{new Date(item.observed_at).toLocaleString("vi-VN")}</time></dd></div>
                  <div className="flex justify-between gap-3"><dt>Confidence</dt><dd className="text-right font-mono text-foreground">{item.confidence ?? "—"}</dd></div>
                  <div className="flex justify-between gap-3"><dt>Evidence ref</dt><dd className="max-w-[70%] break-all text-right font-mono text-foreground">{item.evidence_ref}</dd></div>
                  {item.provenance_ref && <div className="flex justify-between gap-3"><dt>Provenance</dt><dd className="inline-flex max-w-[70%] items-start gap-1 break-all text-right font-mono text-foreground"><ExternalLink className="mt-0.5 size-3 shrink-0" />{item.provenance_ref}</dd></div>}
                </dl>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
