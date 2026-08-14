import { AlertTriangle, Ban, CheckCircle2, CircleHelp, ShieldAlert } from "lucide-react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { cn } from "@/lib/utils";

const toneStyle: Record<SecurityCaseViewModel["risk"]["tone"], string> = {
  safe: "border-emerald-500/30 bg-emerald-500/6 text-emerald-800 dark:text-emerald-200",
  caution: "border-amber-500/30 bg-amber-500/7 text-amber-900 dark:text-amber-200",
  danger: "border-rose-500/30 bg-rose-500/7 text-rose-800 dark:text-rose-200",
  neutral: "border-border bg-muted/45 text-foreground",
};

function RiskIcon({ risk }: { risk: SecurityCaseViewModel["risk"]["value"] }) {
  const Icon = risk === "MALICIOUS"
    ? Ban
    : risk === "HIGH_RISK"
      ? ShieldAlert
      : risk === "SUSPICIOUS"
        ? AlertTriangle
        : risk === "SAFE" || risk === "LOW_RISK"
          ? CheckCircle2
          : CircleHelp;
  return <Icon className="size-5" aria-hidden="true" />;
}

export function ActionRiskPanel({
  viewModel,
  mode,
}: {
  viewModel: SecurityCaseViewModel;
  mode: SecurityPresentationMode;
}) {
  const visibleActions = mode === "simple" ? viewModel.actions.slice(0, 3) : viewModel.actions;
  const [primaryAction, ...supportingActions] = visibleActions;
  return (
    <section aria-labelledby="risk-heading" className="space-y-3">
      <div className="overflow-hidden rounded-2xl border border-foreground/15 bg-foreground text-background">
        <div className="border-b border-background/15 px-4 py-3">
          <p className="text-[9px] font-bold uppercase tracking-[0.2em] opacity-60">Primary recommendation</p>
        </div>
        <div className="p-4">
          {primaryAction ? (
            <>
              <p className="text-lg font-semibold leading-6">{primaryAction.label}</p>
              {mode === "analyst" && <p className="mt-2 font-mono text-[10px] opacity-60">{primaryAction.code} · {primaryAction.policyRef ?? "—"}</p>}
            </>
          ) : (
            <p className="text-sm text-background/70">API chưa trả recommended action.</p>
          )}
        </div>
        {supportingActions.length > 0 && (
          <ul className="border-t border-background/15 px-4 py-3 text-xs leading-5 text-background/80">
            {supportingActions.map((action) => (
              <li key={action.code}>
                {mode === "simple" ? `+ ${action.label}` : (
                  <>+ <span>{action.label}</span><span className="ml-1 font-mono text-[9px] opacity-60">· {action.policyRef ?? "—"}</span></>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className={cn("rounded-2xl border p-4", toneStyle[viewModel.risk.tone])}>
        <div className="flex items-start gap-3">
          <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-background/75"><RiskIcon risk={viewModel.risk.value} /></span>
          <div className="min-w-0 flex-1">
            <p className="micro-label text-current">Risk verdict</p>
            <h2 id="risk-heading" className="mt-1 text-xl font-bold">{viewModel.risk.label}</h2>
            {viewModel.risk.explanation && <p className="mt-2 text-sm leading-6 text-foreground">{viewModel.risk.explanation}</p>}
          </div>
        </div>
        <dl className="mt-4 grid grid-cols-2 gap-2 border-t border-current/15 pt-3 text-xs">
          <div><dt>Risk score</dt><dd className="mt-0.5 text-base font-bold">{viewModel.risk.score ?? "—"}{viewModel.risk.score !== null && "/100"}</dd></div>
          <div><dt>Confidence</dt><dd className="mt-0.5 text-base font-bold">{viewModel.risk.confidence ?? "—"}</dd></div>
        </dl>
        {mode === "analyst" && (
          <dl className="mt-3 space-y-1 border-t border-current/15 pt-3 text-[11px]">
            <div className="flex justify-between gap-3"><dt>Threat type</dt><dd className="text-right font-mono">{viewModel.risk.threatType ?? "—"}</dd></div>
            <div className="flex justify-between gap-3"><dt>Policy</dt><dd className="text-right font-mono">{viewModel.policyVersion ?? "—"}</dd></div>
          </dl>
        )}
      </div>
    </section>
  );
}
