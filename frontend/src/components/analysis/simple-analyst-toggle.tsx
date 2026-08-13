import type { SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { cn } from "@/lib/utils";

export function SimpleAnalystToggle({
  mode,
  onChange,
}: {
  mode: SecurityPresentationMode;
  onChange(mode: SecurityPresentationMode): void;
}) {
  return (
    <div role="group" aria-label="Mức chi tiết" className="inline-flex rounded-xl border border-border bg-card p-1">
      {(["simple", "analyst"] as const).map((option) => (
        <button
          key={option}
          type="button"
          aria-pressed={mode === option}
          onClick={() => onChange(option)}
          className={cn(
            "rounded-lg px-3 py-1.5 text-xs font-semibold capitalize transition-colors",
            mode === option ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground",
          )}
        >
          {option}
        </button>
      ))}
    </div>
  );
}
