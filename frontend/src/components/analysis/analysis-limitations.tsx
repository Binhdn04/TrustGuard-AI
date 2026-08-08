import { Info } from "lucide-react";

export function AnalysisLimitations({ limitations }: { limitations: string[] }) {
  if (limitations.length === 0) return null;
  return (
    <section className="mx-auto max-w-3xl rounded-xl border border-border bg-muted/50 p-5">
      <h2 className="flex items-center gap-2 text-sm font-bold">
        <Info className="size-4" /> Giới hạn của kết quả
      </h2>
      <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
        {limitations.map((limitation, index) => (
          <li key={`${index}:${limitation}`}>{limitation}</li>
        ))}
      </ul>
    </section>
  );
}
