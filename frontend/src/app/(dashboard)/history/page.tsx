"use client";

import { useEffect, useState } from "react";
import { Clock, ShieldAlert, ShieldCheck } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { AnalysisResponse } from "@/types/analysis";

export default function HistoryPage() {
  const [items, setItems] = useState<AnalysisResponse[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    getAnalysisApi()
      .listAnalyses()
      .then((analyses) => {
        if (active) setItems(analyses);
      })
      .catch((caught: unknown) => {
        if (active) {
          setError(caught instanceof Error ? caught.message : "Không tải được lịch sử phân tích.");
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Lịch sử phân tích</h1>
        <p className="mt-1 text-sm text-muted-foreground">Danh sách các nội dung bạn đã yêu cầu hệ thống kiểm tra</p>
      </div>

      {error && <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</p>}

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-muted/50 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-6 py-4 font-semibold">Thời gian</th>
                <th className="w-1/2 px-6 py-4 font-semibold">Kết quả</th>
                <th className="px-6 py-4 text-center font-semibold">Điểm rủi ro</th>
                <th className="px-6 py-4 font-semibold">Trạng thái</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((item) => {
                const dangerous = item.verdict === "malicious" || item.verdict === "suspicious";
                return (
                  <tr key={item.analysis_id} className="transition-colors hover:bg-muted/50">
                    <td className="whitespace-nowrap px-6 py-4 text-muted-foreground">
                      <span className="flex items-center"><Clock className="mr-2 size-4" />{new Date(item.created_at).toLocaleString("vi-VN")}</span>
                    </td>
                    <td className="max-w-[300px] truncate px-6 py-4 font-medium text-foreground">
                      {item.summary ?? item.normalized_urls?.[0] ?? "Đang phân tích…"}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className="inline-flex size-8 items-center justify-center rounded-full bg-secondary font-bold">{item.risk_score ?? "–"}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${dangerous ? "bg-red-100 text-red-800" : "bg-emerald-100 text-emerald-800"}`}>
                        {dangerous ? <ShieldAlert className="mr-1 size-3" /> : <ShieldCheck className="mr-1 size-3" />}
                        {item.status === "completed" ? item.verdict : item.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
              {!loading && items.length === 0 && (
                <tr><td colSpan={4} className="px-6 py-10 text-center text-muted-foreground">Chưa có phiên phân tích nào.</td></tr>
              )}
              {loading && (
                <tr><td colSpan={4} className="px-6 py-10 text-center text-muted-foreground">Đang tải lịch sử…</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
