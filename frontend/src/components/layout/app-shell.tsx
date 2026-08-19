"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";

import { MobileNavigation } from "@/components/layout/mobile-navigation";
import { UserMenu } from "@/components/layout/user-menu";
import { WorkspaceNavigation } from "@/components/layout/workspace-navigation";
import { ThemeToggle } from "@/components/theme-toggle";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAuth } from "@/lib/auth-context";
import type { SecurityCapabilitiesResponseV4 } from "@/types/generated/api-v4";
import { Hexagon, LoaderCircle, PanelLeftClose } from "lucide-react";

const routeCopy: Array<{ match: (pathname: string) => boolean; eyebrow: string; title: string }> = [
  { match: (pathname) => pathname === "/", eyebrow: "SECURITY INTAKE", title: "New investigation" },
  { match: (pathname) => pathname.startsWith("/history"), eyebrow: "CASE ARCHIVE", title: "Cases" },
  { match: (pathname) => pathname.startsWith("/profile"), eyebrow: "ACCOUNT", title: "Tài khoản và cài đặt" },
  { match: (pathname) => pathname.startsWith("/admin/observatory"), eyebrow: "THREAT INTELLIGENCE", title: "Observatory" },
  { match: (pathname) => pathname.startsWith("/admin/review"), eyebrow: "HUMAN REVIEW", title: "Security Review Room" },
  { match: (pathname) => pathname.startsWith("/admin/trust"), eyebrow: "SECURITY V4 TRUST", title: "Trust Control Center" },
  { match: (pathname) => pathname.startsWith("/admin/audit"), eyebrow: "SECURITY V4 AUDIT", title: "Unified Audit" },
  { match: (pathname) => pathname === "/admin", eyebrow: "HUMAN REVIEW", title: "Review room" },
];

export function AppShell({
  children,
  api = getSecurityAnalysisApi(),
}: {
  children: ReactNode;
  api?: SecurityAnalysisApi;
}) {
  const pathname = usePathname();
  const { user, isLoading } = useAuth();
  const userId = user?.id;
  const [capabilities, setCapabilities] = useState<SecurityCapabilitiesResponseV4 | null>(null);

  useEffect(() => {
    if (isLoading || !userId) return;
    let active = true;
    void api.getCapabilities()
      .then((result) => {
        if (active) setCapabilities(result);
      })
      .catch(() => {
        if (active) setCapabilities(null);
      });
    return () => {
      active = false;
    };
  }, [api, isLoading, userId]);

  const currentRoute = useMemo(
    () => routeCopy.find((item) => item.match(pathname)) ?? {
      eyebrow: "AI PROTECT",
      title: "Security workspace",
    },
    [pathname],
  );

  if (isLoading || !user) {
    return (
      <main className="grid min-h-screen place-items-center bg-background px-6 text-center" aria-live="polite">
        <div>
          <LoaderCircle className="mx-auto size-6 animate-spin text-primary" aria-hidden="true" />
          <p className="mt-3 text-sm font-medium">Đang xác minh phiên đăng nhập…</p>
          <p className="mt-1 text-xs text-muted-foreground">Workspace chỉ tải dữ liệu sau khi auth bootstrap hoàn tất.</p>
        </div>
      </main>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <a
        href="#workspace-content"
        className="fixed left-4 top-3 z-50 -translate-y-20 rounded-lg bg-foreground px-4 py-2 text-sm font-semibold text-background focus:translate-y-0"
      >
        Bỏ qua điều hướng
      </a>

      <aside className="fixed inset-y-0 left-0 z-30 hidden w-72 border-r border-border/80 bg-card/92 px-5 py-6 backdrop-blur-xl lg:block">
        <div className="flex items-center gap-3 px-2">
          <span className="relative grid size-11 place-items-center text-primary" aria-hidden="true">
            <Hexagon className="absolute size-11 stroke-[1.25]" />
            <span className="size-2 rounded-full bg-primary shadow-[0_0_0_6px_color-mix(in_srgb,var(--primary)_16%,transparent)]" />
          </span>
          <div>
            <p className="text-[11px] font-bold tracking-[0.24em] text-muted-foreground">AI PROTECT</p>
            <p className="text-base font-semibold tracking-tight">Investigation desk</p>
          </div>
        </div>

        <WorkspaceNavigation
          pathname={pathname}
          role={user?.role ?? "user"}
          capabilities={capabilities}
          className="mt-10"
        />

        <div className="absolute inset-x-5 bottom-6 border-t border-border/70 pt-5">
          <div className="flex items-start gap-3 rounded-xl bg-muted/60 p-3">
            <PanelLeftClose className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <p className="text-xs leading-5 text-muted-foreground">
              Case chỉ hiển thị dữ liệu phân tích và bằng chứng do API trả về.
            </p>
          </div>
        </div>
      </aside>

      <div className="min-w-0 lg:pl-72">
        <header className="sticky top-0 z-20 border-b border-border/75 bg-background/88 backdrop-blur-xl">
          <div className="flex h-16 items-center justify-between gap-4 px-4 sm:px-7 lg:h-[72px] lg:px-9">
            <div className="min-w-0">
              <p className="truncate text-[10px] font-bold tracking-[0.2em] text-primary">{currentRoute.eyebrow}</p>
              <p className="truncate text-sm font-semibold sm:text-base">{currentRoute.title}</p>
            </div>
            <div className="flex items-center gap-2">
              <ThemeToggle />
              <UserMenu />
            </div>
          </div>
        </header>

        <main id="workspace-content" tabIndex={-1} className="mx-auto w-full max-w-[1600px] px-4 py-6 pb-28 sm:px-7 lg:px-9 lg:py-8 lg:pb-10">
          {children}
        </main>
      </div>

      <MobileNavigation
        pathname={pathname}
        role={user?.role ?? "user"}
        capabilities={capabilities}
      />
    </div>
  );
}
