"use client";

import { useCallback, useEffect, useState } from "react";
import Image from "next/image";
import { AlertTriangle, Camera, Clock3, ImageOff, Loader2, RefreshCw } from "lucide-react";

import { getAnalysisApi } from "@/lib/api/analysis-api";
import type { ScreenshotStatusResponseV3 } from "@/types/generated/api-v3";

export function ScreenshotArtifactPanel({
  analysisId,
  requested,
}: {
  analysisId: string;
  requested: boolean;
}) {
  const [result, setResult] = useState<ScreenshotStatusResponseV3 | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const response = await getAnalysisApi().getScreenshotStatus(analysisId);
      setResult(response);
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Không thể tải trạng thái ảnh chụp.");
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    void Promise.resolve().then(load);
  }, [load]);

  useEffect(() => {
    if (result?.status !== "pending") return;
    const timer = window.setInterval(() => void load(), 3_000);
    return () => window.clearInterval(timer);
  }, [load, result?.status]);

  return (
    <section className="mx-auto max-w-3xl overflow-hidden rounded-2xl border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border p-5">
        <span className="grid size-9 place-items-center rounded-xl bg-violet-500/10 text-violet-600"><Camera className="size-4" /></span>
        <div className="flex-1"><h2 className="text-sm font-semibold">Ảnh chụp trang web an toàn</h2><p className="mt-0.5 text-xs text-muted-foreground">Artifact ảnh tĩnh từ trình duyệt sandbox, không hiển thị HTML của trang.</p></div>
        {!loading && <button type="button" aria-label="Làm mới trạng thái ảnh chụp" onClick={() => { setLoading(true); void load(); }} className="rounded-lg p-2 text-muted-foreground hover:bg-muted"><RefreshCw className="size-4" /></button>}
      </div>

      <div className="p-5">
        {loading && <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />Đang kiểm tra artifact…</div>}
        {error && <div role="alert" className="flex gap-2 text-sm text-rose-600"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{error}</div>}
        {!loading && !error && (!requested || result?.status === "not_requested") && <div className="flex gap-3 text-sm text-muted-foreground"><ImageOff className="size-5 shrink-0" /><p>Bạn không cấp quyền chụp ảnh cho phiên này. Phân tích nội dung vẫn được thực hiện bình thường.</p></div>}
        {!loading && !error && result?.status === "pending" && <div className="flex gap-3 text-sm text-muted-foreground"><Clock3 className="size-5 shrink-0 text-amber-500" /><p>Ảnh chụp đang được xử lý trong môi trường cô lập. Trạng thái sẽ tự động cập nhật.</p></div>}
        {!loading && !error && result?.status === "failed" && <div className="flex gap-3 text-sm text-muted-foreground"><ImageOff className="size-5 shrink-0" /><p>Không tạo được ảnh chụp cho URL này. Kết quả phân tích không bị ảnh hưởng.</p></div>}
        {!loading && !error && result?.status === "expired" && <div className="flex gap-3 text-sm text-muted-foreground"><ImageOff className="size-5 shrink-0" /><p>Artifact đã hết thời hạn lưu trữ và không còn khả dụng.</p></div>}
        {!loading && !error && result?.status === "ready" && result.artifact && (
          <figure className="space-y-3">
            {/* The backend only serves verified PNG/JPEG/WebP bytes with nosniff and a short-lived signed URL. */}
            <div className="relative h-[min(60vh,520px)] w-full overflow-hidden rounded-xl border border-border bg-muted">
              <Image
                src={result.artifact.access_path}
                alt="Ảnh chụp trang web được tạo trong sandbox"
                fill
                unoptimized
                referrerPolicy="no-referrer"
                className="object-contain"
              />
            </div>
            <figcaption className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground">
              <span>{result.artifact.media_type} · {(result.artifact.size_bytes / 1024).toFixed(1)} KB</span>
              <span>Hết hạn {new Date(result.artifact.expires_at).toLocaleString("vi-VN")}</span>
            </figcaption>
          </figure>
        )}
      </div>
    </section>
  );
}
