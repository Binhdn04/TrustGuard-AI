"use client";

import Image from "next/image";
import { Camera, CameraOff, LoaderCircle, X, ZoomIn } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";

type CaptureState = {
  imageUrl: string | null;
  loading: boolean;
  error: string | null;
};

function captureErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message.toLocaleLowerCase("en") : "";
  if (message.includes("timed out") || message.includes("timeout")) {
    return "Trang web phản hồi quá chậm nên chưa thể tạo ảnh xem trước.";
  }
  if (message.includes("downloadable") || message.includes("download")) {
    return "Liên kết này dẫn tới tệp tải xuống nên AI PROTECT không mở để chụp ảnh.";
  }
  return "Không thể tạo ảnh xem trước. Trang web có thể đang chặn truy cập tự động.";
}

export function PageCapturePanel({
  analysisId,
  urls,
  api,
}: {
  analysisId: string;
  urls: string[];
  api: SecurityAnalysisApi;
}) {
  const [enabled, setEnabled] = useState(false);
  const [capture, setCapture] = useState<CaptureState>({ imageUrl: null, loading: true, error: null });
  const [zoomed, setZoomed] = useState(false);
  const attemptedCaptures = useRef(new Set<string>());
  const currentObjectUrl = useRef<string | null>(null);
  const latestIndex = Math.max(urls.length - 1, 0);
  const latestUrl = urls.at(-1) ?? "";
  const captureKey = `${analysisId}:${latestIndex}:${latestUrl}`;
  const { imageUrl, loading, error } = capture;

  useEffect(() => () => {
    if (currentObjectUrl.current) URL.revokeObjectURL(currentObjectUrl.current);
    currentObjectUrl.current = null;
  }, []);

  useEffect(() => {
    let active = true;
    void Promise.resolve(api.getCapabilities())
      .then((capabilities) => {
        if (active) setEnabled(capabilities.security_page_capture === true);
      })
      .catch(() => {
        if (active) setEnabled(false);
      });
    return () => {
      active = false;
    };
  }, [api]);

  useEffect(() => {
    const capturePage = api.capturePage;
    const attempts = attemptedCaptures.current;
    if (!enabled || !latestUrl || !capturePage || attempts.has(captureKey)) return;

    attempts.add(captureKey);
    if (currentObjectUrl.current) {
      URL.revokeObjectURL(currentObjectUrl.current);
      currentObjectUrl.current = null;
    }
    setZoomed(false);
    setCapture({ imageUrl: null, loading: true, error: null });
    let active = true;
    let started = false;
    let settled = false;
    const timer = window.setTimeout(() => {
      if (!active) return;
      started = true;
      void Promise.resolve(capturePage.call(api, analysisId, latestIndex))
        .then((image) => {
          settled = true;
          const nextUrl = URL.createObjectURL(image);
          if (!active) {
            URL.revokeObjectURL(nextUrl);
            return;
          }
          currentObjectUrl.current = nextUrl;
          setCapture({ imageUrl: nextUrl, loading: false, error: null });
        })
        .catch((caught) => {
          settled = true;
          if (!active) return;
          setCapture({ imageUrl: null, loading: false, error: captureErrorMessage(caught) });
        });
    }, 0);

    return () => {
      active = false;
      window.clearTimeout(timer);
      if (!started || !settled) attempts.delete(captureKey);
    };
  }, [analysisId, api, captureKey, enabled, latestIndex, latestUrl]);

  useEffect(() => {
    if (!zoomed) return;
    const previousOverflow = document.body.style.overflow;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setZoomed(false);
    };
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [zoomed]);

  if (!enabled || urls.length === 0 || !api.capturePage) return null;

  return (
    <section aria-labelledby="page-capture-heading" className="rounded-2xl border border-border bg-background/45 p-4">
      <h3 id="page-capture-heading" className="flex items-center gap-2 text-sm font-semibold">
        <Camera className="size-4 text-primary" aria-hidden="true" />
        Xem trước trang web
      </h3>

      <div className="mt-4 overflow-hidden rounded-xl border border-border bg-muted/30">
        <div className="flex aspect-video items-center justify-center">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
              <LoaderCircle className="size-4 animate-spin text-primary" aria-hidden="true" />
              Đang tạo ảnh xem trước…
            </div>
          )}
          {!loading && error && (
            <div className="max-w-md px-6 text-center" role="alert">
              <CameraOff className="mx-auto size-6 text-muted-foreground" aria-hidden="true" />
              <p className="mt-2 text-sm text-muted-foreground">{error}</p>
            </div>
          )}
          {!loading && imageUrl && (
            <button
              type="button"
              onClick={() => setZoomed(true)}
              aria-label="Phóng to ảnh chụp trang web"
              className="group relative block size-full cursor-zoom-in focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-inset"
            >
              <Image
                src={imageUrl}
                alt={`Ảnh chụp trang đích ${latestUrl}`}
                width={1280}
                height={720}
                unoptimized
                className="size-full object-contain"
              />
              <span className="absolute bottom-3 right-3 inline-flex items-center gap-1.5 rounded-full bg-black/70 px-3 py-1.5 text-xs font-medium text-white opacity-0 shadow-sm transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                <ZoomIn className="size-3.5" aria-hidden="true" />
                Phóng to
              </span>
            </button>
          )}
        </div>
        <p className="truncate border-t border-border px-3 py-2 text-[10px] text-muted-foreground" title={latestUrl}>
          {latestUrl}
        </p>
      </div>

      {imageUrl && zoomed && createPortal(
        (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Ảnh chụp trang web phóng to"
            onClick={() => setZoomed(false)}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/85 p-4 backdrop-blur-sm sm:p-8"
          >
            <div
              className="relative flex max-h-full max-w-full items-center justify-center"
              onClick={(event) => event.stopPropagation()}
            >
              <Image
                src={imageUrl}
                alt={`Ảnh chụp phóng to của ${latestUrl}`}
                width={1280}
                height={720}
                unoptimized
                className="max-h-[calc(100vh-2rem)] w-auto max-w-[calc(100vw-2rem)] rounded-xl object-contain shadow-2xl sm:max-h-[calc(100vh-4rem)] sm:max-w-[calc(100vw-4rem)]"
              />
              <button
                type="button"
                autoFocus
                onClick={() => setZoomed(false)}
                aria-label="Đóng ảnh phóng to"
                className="absolute right-2 top-2 inline-flex size-10 items-center justify-center rounded-full bg-black/75 text-white shadow-lg transition-colors hover:bg-black focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
              >
                <X className="size-5" aria-hidden="true" />
              </button>
            </div>
          </div>
        ),
        document.body,
      )}
    </section>
  );
}
