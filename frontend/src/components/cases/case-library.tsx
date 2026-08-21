"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Archive, ChevronLeft, ChevronRight, Loader2, RotateCw } from "lucide-react";

import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import {
  securityHistoryHref,
  toSecurityAnalysisPageQuery,
  type SecurityHistoryQuery,
} from "@/lib/mappers/security-history-query";
import type { SecurityAnalysisPageV4 } from "@/types/generated/api-v4";

import { CaseList } from "./case-list";
import { CaseListFilters } from "./case-list-filters";

type PaginationItem = number | "ellipsis";

function paginationItems(currentPage: number, totalPages: number): PaginationItem[] {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  if (currentPage <= 4) return [1, 2, 3, 4, 5, "ellipsis", totalPages];
  if (currentPage >= totalPages - 3) {
    return [1, "ellipsis", totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
  }
  return [1, "ellipsis", currentPage - 1, currentPage, currentPage + 1, "ellipsis", totalPages];
}

export function CaseLibrary({
  initialQuery,
  api = getSecurityAnalysisApi(),
}: {
  initialQuery: SecurityHistoryQuery;
  api?: SecurityAnalysisApi;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [query, setQuery] = useState(initialQuery);
  const [page, setPage] = useState<SecurityAnalysisPageV4 | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const load = useCallback(async (activeQuery: SecurityHistoryQuery) => {
    const generation = ++requestGeneration.current;
    setLoading(true);
    setError(null);
    try {
      const response = await api.pageAnalyses(toSecurityAnalysisPageQuery(activeQuery));
      if (generation === requestGeneration.current) setPage(response);
    } catch (loadError) {
      if (generation === requestGeneration.current) {
        setError(loadError instanceof Error ? loadError.message : "Không thể tải case history.");
      }
    } finally {
      if (generation === requestGeneration.current) setLoading(false);
    }
  }, [api]);

  useEffect(() => { void Promise.resolve().then(() => load(query)); }, [load, query]);

  const changeQuery = (next: SecurityHistoryQuery) => {
    setQuery(next);
    const href = securityHistoryHref(next);
    if (`${pathname}${window.location.search}` !== href) router.replace(href, { scroll: false });
  };

  const totalPages = page ? Math.max(1, Math.ceil(page.total / page.limit)) : 1;
  const visiblePages = paginationItems(query.page, totalPages);
  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <header className="mb-7 border-b border-border/70 pb-6">
        <h1 className="text-3xl font-bold tracking-[-0.025em]">Lịch sử trò chuyện</h1>
      </header>

      <CaseListFilters query={query} disabled={loading} onChange={changeQuery} />

      <div aria-live="polite" className="mt-6">
        {loading && (
          <div role="status" className="grid min-h-48 place-items-center rounded-2xl border border-border bg-card">
            <span className="inline-flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-5 animate-spin" />Đang tải case</span>
          </div>
        )}
        {error && !loading && (
          <div role="alert" className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-5 text-sm text-rose-800 dark:text-rose-200">
            <p>{error}</p>
            <button type="button" onClick={() => void load(query)} className="mt-3 inline-flex items-center gap-2 font-bold underline underline-offset-4"><RotateCw className="size-4" />Thử lại</button>
          </div>
        )}
        {!loading && !error && page && (
          <>
            <div className="mb-3 flex items-center justify-between text-xs text-muted-foreground">
            <span>{page.total} cuộc trò chuyện</span>
              <span>Trang {query.page}/{totalPages}</span>
            </div>
            {page.items.length > 0 ? <CaseList items={page.items} /> : (
              <div className="grid min-h-48 place-items-center rounded-2xl border border-dashed border-border text-center text-muted-foreground">
                <div><Archive className="mx-auto size-6" /><p className="mt-2 text-sm font-semibold">Chưa có cuộc trò chuyện phù hợp</p><p className="mt-1 text-xs">Thử đổi từ khóa hoặc mức rủi ro.</p></div>
              </div>
            )}
            {page.total > 0 && (
              <nav aria-label="Phân trang case" className="mt-5 flex flex-wrap items-center justify-center gap-2">
                <button type="button" disabled={query.page <= 1} onClick={() => changeQuery({ ...query, page: query.page - 1 })} className="inline-flex items-center gap-1 rounded-xl border border-border bg-card px-3 py-2 text-xs font-semibold disabled:opacity-40"><ChevronLeft className="size-4" />Trang trước</button>
                {visiblePages.map((item, index) => item === "ellipsis" ? (
                  <span key={`ellipsis-${index}`} aria-hidden="true" className="px-1 text-sm text-muted-foreground">…</span>
                ) : (
                  <button
                    key={item}
                    type="button"
                    aria-label={`Trang ${item}`}
                    aria-current={item === query.page ? "page" : undefined}
                    onClick={() => changeQuery({ ...query, page: item })}
                    className={`grid size-9 place-items-center rounded-xl border text-xs font-bold transition-colors ${
                      item === query.page
                        ? "border-primary bg-primary text-primary-foreground"
                        : "border-border bg-card hover:border-primary/50 hover:text-primary"
                    }`}
                  >
                    {item}
                  </button>
                ))}
                <button type="button" disabled={query.page >= totalPages} onClick={() => changeQuery({ ...query, page: query.page + 1 })} className="inline-flex items-center gap-1 rounded-xl border border-border bg-card px-3 py-2 text-xs font-semibold disabled:opacity-40">Trang sau<ChevronRight className="size-4" /></button>
              </nav>
            )}
          </>
        )}
      </div>
    </div>
  );
}
