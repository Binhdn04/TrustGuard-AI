"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Filter,
  HelpCircle,
  Loader2,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import { mapAnalysisResponseToViewModel } from "@/lib/mappers/analysis-v3-mapper";
import { cn } from "@/lib/utils";
import type { AnalysisResponseV3 } from "@/types/generated/api-v3";
import type { ClaimStance } from "@/types/analysis-view-model";

type FilterType = "all" | ClaimStance | "url_warning";

function displayForStance(stance: ClaimStance) {
  switch (stance) {
    case "supports":
      return { label: "Được xác nhận", icon: ShieldCheck, color: "text-emerald-600 bg-emerald-500/10 border-emerald-500/20" };
    case "refutes":
      return { label: "Bị bác bỏ", icon: ShieldAlert, color: "text-rose-700 dark:text-rose-300 bg-rose-500/10 border-rose-500/20" };
    case "mixed":
      return { label: "Đúng một phần", icon: AlertTriangle, color: "text-amber-600 bg-amber-500/10 border-amber-500/20" };
    default:
      return { label: "Chưa rõ", icon: HelpCircle, color: "text-muted-foreground bg-muted/50 border-border" };
  }
}

export default function HistoryPage() {
  const [items, setItems] = useState<AnalysisResponseV3[]>([]);
  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState<FilterType>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await getAnalysisApi().listAnalyses());
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Không thể tải lịch sử kiểm chứng.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    void getAnalysisApi().listAnalyses()
      .then((response) => { if (active) setItems(response); })
      .catch((loadError: unknown) => {
        if (active) setError(loadError instanceof Error ? loadError.message : "Không thể tải lịch sử kiểm chứng.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const history = useMemo(() => items.map((response) => {
    const originalContent = response.claims?.join(" ") || response.summary || `Phân tích ${response.analysis_id}`;
    const view = mapAnalysisResponseToViewModel(response, {
      originalContent,
      consentToScanUrls: true,
    });
    return {
      id: response.analysis_id,
      content: originalContent,
      stance: view.factCheck?.overallStance ?? "unrated",
      claimsCount: response.claims?.length ?? 0,
      sourcesCount: (response.evidence ?? []).filter((evidence) => evidence.type === "fact_check" || evidence.type === "official_source").length,
      hasUrlWarning: Boolean(response.normalized_urls?.length) && (response.verdict === "malicious" || response.verdict === "suspicious"),
      urls: response.normalized_urls ?? [],
      date: response.completed_at ?? response.created_at,
      status: response.status,
    };
  }), [items]);

  const filteredHistory = history.filter((item) => {
    if (search && !item.content.toLowerCase().includes(search.toLowerCase())) return false;
    if (activeFilter === "all") return true;
    if (activeFilter === "url_warning") return item.hasUrlWarning;
    return item.stance === activeFilter;
  });

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Lịch sử kiểm chứng</h1>
        <p className="mt-2 text-muted-foreground">Dữ liệu được tải từ các phiên phân tích của tài khoản hiện tại.</p>
      </div>

      <div className="mb-6 flex flex-col gap-4 sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <input aria-label="Tìm kiếm lịch sử" placeholder="Tìm kiếm nội dung…" value={search} onChange={(event) => setSearch(event.target.value)} className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-4 text-sm outline-none focus:border-primary" />
        </div>
        <div className="relative w-full shrink-0 sm:w-52">
          <Filter className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <select aria-label="Lọc lịch sử" value={activeFilter} onChange={(event) => setActiveFilter(event.target.value as FilterType)} className="w-full appearance-none rounded-xl border border-border bg-background py-2 pl-9 pr-4 text-sm">
            <option value="all">Tất cả kết quả</option>
            <option value="supports">Được xác nhận</option>
            <option value="refutes">Bị bác bỏ</option>
            <option value="mixed">Đúng một phần</option>
            <option value="unrated">Chưa đủ bằng chứng</option>
            <option value="url_warning">Có URL cảnh báo</option>
          </select>
        </div>
      </div>

      {loading && <div aria-live="polite" className="flex justify-center py-16"><Loader2 className="size-7 animate-spin text-primary" /></div>}
      {error && (
        <div role="alert" className="rounded-2xl border border-rose-200 bg-rose-50 p-5 text-sm text-rose-700">
          {error} <button type="button" onClick={() => void load()} className="ml-2 font-bold underline">Thử lại</button>
        </div>
      )}
      {!loading && !error && (
        <div className="space-y-4">
          {filteredHistory.map((item) => {
            const display = displayForStance(item.stance);
            const Icon = display.icon;
            return (
              <article key={item.id} className="rounded-2xl border border-border bg-card p-5">
                <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                  <div className="min-w-0 flex-1 space-y-2">
                    <p className="line-clamp-2 text-sm font-medium">&quot;{item.content}&quot;</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(item.date).toLocaleDateString("vi-VN")} · {item.claimsCount} claim · {item.sourcesCount} nguồn · {item.status}
                    </p>
                    {item.urls.map((url) => <p key={url} className="break-all text-xs text-muted-foreground">URL: {url}</p>)}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold", display.color)}><Icon className="size-3.5" />{display.label}</span>
                    {item.hasUrlWarning && <span className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/20 bg-rose-500/10 px-2.5 py-1 text-xs font-semibold text-rose-700 dark:text-rose-300"><AlertTriangle className="size-3.5" />URL cảnh báo</span>}
                  </div>
                </div>
              </article>
            );
          })}
          {filteredHistory.length === 0 && <div className="rounded-2xl border border-dashed border-border py-12 text-center text-muted-foreground">Chưa có kết quả phù hợp.</div>}
        </div>
      )}
    </div>
  );
}
