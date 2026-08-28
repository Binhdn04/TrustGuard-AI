import type { SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type { SecurityProgressViewModel } from "@/lib/security-progress";

export function ControlledProgressCard({
  progress,
  mode,
}: {
  progress: SecurityProgressViewModel;
  mode: SecurityPresentationMode;
}) {
  const label = progress.latest?.label ?? "Trợ lý đang kiểm tra nội dung";

  return (
    <div className="max-w-[94%] rounded-2xl rounded-bl-sm border border-primary/20 bg-primary/5 p-4">
      <div className="flex items-center gap-3">
        <span className="relative flex size-2.5" aria-hidden="true">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary opacity-40 motion-reduce:animate-none" />
          <span className="relative inline-flex size-2.5 rounded-full bg-primary" />
        </span>
        <p role="status" aria-live="polite" aria-atomic="true" className="text-sm font-semibold">
          {label}
        </p>
      </div>
      {mode === "analyst" && progress.timeline.length > 0 && (
        <ol aria-label="Tiến trình kiểm tra" aria-live="off" className="mt-3 space-y-1 border-l border-primary/20 pl-3 text-xs text-muted-foreground">
          {progress.timeline.map((entry) => (
            <li key={entry.eventId}>{entry.label}</li>
          ))}
        </ol>
      )}
    </div>
  );
}
