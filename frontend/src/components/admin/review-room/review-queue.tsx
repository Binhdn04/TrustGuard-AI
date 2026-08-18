import { FileWarning, MessageSquareWarning, RefreshCw, Search } from "lucide-react";

import { cn } from "@/lib/utils";
import type {
  SecurityAppealAdminRecordV4,
  SecurityReportAdminRecordV4,
} from "@/types/generated/api-v4";

export type FeedbackKind = "report" | "appeal";
export type FeedbackReviewItem =
  | { kind: "report"; record: SecurityReportAdminRecordV4 }
  | { kind: "appeal"; record: SecurityAppealAdminRecordV4 };

export function feedbackKey(item: FeedbackReviewItem): string {
  return item.kind === "report" ? `report:${item.record.report_id}` : `appeal:${item.record.appeal_id}`;
}

function statusTone(status: string): string {
  if (status === "processed" || status === "resolved") return "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (status === "reviewing" || status === "under_review") return "border-blue-500/25 bg-blue-500/10 text-blue-700 dark:text-blue-300";
  return "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300";
}

export function ReviewQueue({
  kind,
  items,
  selectedKey,
  query,
  status,
  loading,
  error,
  page,
  total,
  pageSize,
  onKindChange,
  onQueryChange,
  onStatusChange,
  onSelect,
  onPageChange,
  onRetry,
}: {
  kind: FeedbackKind;
  items: FeedbackReviewItem[];
  selectedKey: string | null;
  query: string;
  status: string;
  loading: boolean;
  error: string | null;
  page: number;
  total: number;
  pageSize: number;
  onKindChange: (kind: FeedbackKind) => void;
  onQueryChange: (query: string) => void;
  onStatusChange: (status: string) => void;
  onSelect: (item: FeedbackReviewItem) => void;
  onPageChange: (page: number) => void;
  onRetry: () => void;
}) {
  const statusOptions = kind === "report"
    ? ["all", "submitted", "reviewing", "processed"]
    : ["all", "submitted", "under_review", "resolved"];
  const lastPage = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section aria-labelledby="review-queue-heading" className="overflow-hidden rounded-2xl border border-border bg-card">
      <div className="border-b border-border p-4">
        <p className="micro-label">Feedback queue</p>
        <h2 id="review-queue-heading" className="mt-1 font-semibold">Cases requiring human review</h2>
        <div className="mt-4 grid grid-cols-2 rounded-xl bg-muted p-1" role="tablist" aria-label="Loại feedback">
          {(["report", "appeal"] as const).map((value) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={kind === value}
              onClick={() => onKindChange(value)}
              className={cn("rounded-lg px-3 py-2 text-xs font-semibold capitalize", kind === value ? "bg-background shadow-sm" : "text-muted-foreground")}
            >
              {value === "report" ? "Reports" : "Appeals"}
            </button>
          ))}
        </div>
        <div className="mt-3 grid gap-2 sm:grid-cols-[1fr_auto] xl:grid-cols-1">
          <label className="relative">
            <span className="sr-only">Tìm feedback</span>
            <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Analysis, owner, reason…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" />
          </label>
          <select aria-label="Lọc feedback theo trạng thái" value={status} onChange={(event) => onStatusChange(event.target.value)} className="rounded-xl border border-border bg-background px-3 py-2 text-sm">
            {statusOptions.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}
          </select>
        </div>
      </div>

      {loading && <p role="status" className="p-5 text-sm text-muted-foreground">Đang tải hàng đợi…</p>}
      {error && <div role="alert" className="m-4 rounded-xl border border-rose-500/25 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 inline-flex items-center gap-1 font-semibold underline"><RefreshCw className="size-3" />Thử lại</button></div>}
      {!loading && !error && (
        <div className="divide-y divide-border">
          {items.map((item) => {
            const key = feedbackKey(item);
            const record = item.record;
            const Icon = item.kind === "report" ? FileWarning : MessageSquareWarning;
            return (
              <button key={key} type="button" aria-pressed={selectedKey === key} onClick={() => onSelect(item)} className={cn("flex w-full gap-3 p-4 text-left transition-colors hover:bg-muted/45", selectedKey === key && "bg-primary/8") }>
                <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"><Icon className="size-4" /></span>
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase", statusTone(record.status))}>{record.status.replaceAll("_", " ")}</span>
                    <time className="text-[10px] text-muted-foreground" dateTime={record.created_at}>{new Date(record.created_at).toLocaleString("vi-VN")}</time>
                  </span>
                  <span className="mt-2 line-clamp-2 block text-sm font-semibold">{record.reason}</span>
                  <span className="mt-1 block truncate font-mono text-[10px] text-muted-foreground">{record.analysis_id}</span>
                </span>
              </button>
            );
          })}
          {items.length === 0 && <p className="p-8 text-center text-sm text-muted-foreground">Không có feedback phù hợp.</p>}
        </div>
      )}
      <div className="flex items-center justify-between border-t border-border px-4 py-3 text-xs text-muted-foreground">
        <span>{total} records</span>
        <span className="flex items-center gap-2">
          <button type="button" aria-label="Feedback page trước" disabled={page <= 1 || loading} onClick={() => onPageChange(page - 1)} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>
          {page}/{lastPage}
          <button type="button" aria-label="Feedback page sau" disabled={page >= lastPage || loading} onClick={() => onPageChange(page + 1)} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button>
        </span>
      </div>
    </section>
  );
}
