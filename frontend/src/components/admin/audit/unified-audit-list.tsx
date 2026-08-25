import { ChevronDown, FileClock, Search } from "lucide-react";

import { securityLabel } from "@/lib/presentation/security-labels";
import type { SecurityAdminAuditPageV4, SecurityAuditResourceV4 } from "@/types/generated/api-v4";

export interface UnifiedAuditQuery {
  resourceType: "all" | SecurityAuditResourceV4;
  action: string;
  page: number;
}

const resourceLabels: Record<SecurityAuditResourceV4, string> = {
  brand: "Thương hiệu",
  whitelist: "Ngoại lệ",
  memory: "Bộ nhớ",
  campaign: "Chiến dịch",
  report: "Báo cáo",
  appeal: "Khiếu nại",
  copilot: "Gợi ý hỗ trợ",
  identity_candidate: "Danh tính",
  blacklist: "Danh sách chặn",
};

export function UnifiedAuditList({
  page,
  query,
  loading,
  error,
  onQueryChange,
  onRetry,
}: {
  page: SecurityAdminAuditPageV4 | null;
  query: UnifiedAuditQuery;
  loading: boolean;
  error: string | null;
  onQueryChange: (query: UnifiedAuditQuery) => void;
  onRetry: () => void;
}) {
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 20)));

  return (
    <section aria-labelledby="unified-audit-heading" className="space-y-4">
      <h2 id="unified-audit-heading" className="text-lg font-semibold">Sự kiện quản trị</h2>
      <div className="grid gap-2 sm:grid-cols-[auto_1fr]">
        <select
          aria-label="Lọc lịch sử theo loại tài nguyên"
          value={query.resourceType}
          onChange={(event) => onQueryChange({
            ...query,
            resourceType: event.target.value as UnifiedAuditQuery["resourceType"],
            page: 1,
          })}
          className="rounded-xl border border-border bg-background px-3 py-2 text-sm"
        >
          <option value="all">Tất cả loại</option>
          {(Object.keys(resourceLabels) as SecurityAuditResourceV4[]).map((item) => (
            <option key={item} value={item}>{resourceLabels[item]}</option>
          ))}
        </select>
        <label className="relative">
          <span className="sr-only">Lọc lịch sử theo hành động</span>
          <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
          <input
            aria-label="Lọc lịch sử theo hành động"
            value={query.action}
            onChange={(event) => onQueryChange({ ...query, action: event.target.value, page: 1 })}
            placeholder="Tìm hành động…"
            className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm"
          />
        </label>
      </div>

      {error && (
        <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
          {error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button>
        </p>
      )}

      {loading ? (
        <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang tải lịch sử…</p>
      ) : (
        <div className="space-y-2">
          {page?.items.map((event) => (
            <article key={event.audit_id} className="rounded-2xl border border-border bg-card p-4">
              <div className="flex items-start gap-3">
                <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
                  <FileClock className="size-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">
                      {resourceLabels[event.resource_type]}
                    </span>
                    <strong>{securityLabel(event.action)}</strong>
                    <time className="text-[10px] text-muted-foreground" dateTime={event.occurred_at}>
                      {new Date(event.occurred_at).toLocaleString("vi-VN")}
                    </time>
                  </div>
                  {event.note && <p className="mt-2 text-sm leading-6">{event.note}</p>}
                  <details className="group mt-3 border-t border-border pt-2">
                    <summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">
                      Chi tiết kỹ thuật
                      <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" aria-hidden="true" />
                    </summary>
                    <div className="mt-2 space-y-2 text-[10px] text-muted-foreground">
                      <p className="break-all font-mono">Mã tài nguyên {event.resource_id} · Người thực hiện {event.actor_id}</p>
                      {event.evidence_refs.length > 0 && (
                        <ul className="space-y-1">
                          {event.evidence_refs.map((ref) => <li key={ref} className="break-all font-mono">{ref}</li>)}
                        </ul>
                      )}
                    </div>
                  </details>
                </div>
              </div>
            </article>
          ))}
          {page?.items.length === 0 && (
            <p className="rounded-2xl border border-dashed border-border p-12 text-center text-sm text-muted-foreground">
              Không có sự kiện phù hợp.
            </p>
          )}
        </div>
      )}

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{page?.total ?? 0} sự kiện</span>
        <span className="flex items-center gap-2">
          <button aria-label="Trang lịch sử trước" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>
          {query.page}/{lastPage}
          <button aria-label="Trang lịch sử sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button>
        </span>
      </div>
    </section>
  );
}
