"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  ClockIcon,
  LockIcon,
  SearchIcon,
  ShieldIcon,
  ChartIcon,
  UsersIcon,
} from "@/components/ui/icons";
import { ThemeToggle } from "@/components/theme-toggle";
import { UserMenu } from "@/components/layout/user-menu";
import { useAuth } from "@/lib/auth-context";

const navigation = [
  { label: "Phân tích", icon: SearchIcon, href: "/" },
  { label: "Lịch sử", icon: ClockIcon, href: "/history" },
  { label: "Admin review", icon: UsersIcon, href: "/admin", adminOnly: true },
  { label: "Vận hành", icon: ChartIcon, href: "/admin/platform", adminOnly: true },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-background text-foreground transition-colors duration-300">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-border bg-card px-4 py-6 text-card-foreground lg:flex transition-colors duration-300">
        <div className="flex items-center gap-3 px-2">
          <span className="grid size-10 place-items-center rounded-xl bg-primary text-primary-foreground shadow-[0_0_30px_rgba(16,185,129,0.2)]">
            <ShieldIcon className="size-6" />
          </span>
          <div>
            <p className="text-lg font-bold tracking-tight">AI PROTECT</p>
            <p className="text-xs text-muted-foreground">Trust intelligence</p>
          </div>
        </div>

        <nav aria-label="Điều hướng chính" className="mt-10 space-y-2">
          {navigation.map(({ label, icon: Icon, href, adminOnly }) => {
            if (adminOnly && user?.role !== "security_admin") return null;
            const active = pathname === href;

            return (
              <Link
                key={label}
                href={href}
                className={`flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-sm font-medium transition-colors ${
                  active
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                }`}
              >
                <Icon className="size-5" />
                {label}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto rounded-2xl border border-border bg-background/50 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-primary">
            <LockIcon className="size-4" />
            Quyền riêng tư
          </div>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">
            Chỉ nội dung bạn chủ động gửi mới được đưa vào phiên phân tích.
          </p>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur-xl transition-colors duration-300">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-4 sm:px-8">
            <div className="flex items-center gap-3 lg:hidden">
              <span className="grid size-9 place-items-center rounded-xl bg-primary/10 text-primary">
                <ShieldIcon className="size-5" />
              </span>
              <span className="font-bold">AI PROTECT</span>
            </div>
            <div className="hidden lg:block">
              <p className="text-sm font-semibold">Trung tâm phân tích</p>
              <p className="text-xs text-muted-foreground">Kiểm tra tin nhắn và URL đáng ngờ</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="hidden items-center gap-2 rounded-full bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-700 sm:flex dark:bg-emerald-500/20 dark:text-emerald-400">
                <span className="size-1.5 rounded-full bg-emerald-500" />
                Hệ thống sẵn sàng
              </span>
              <ThemeToggle />
              <UserMenu />
            </div>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-5 py-8 sm:px-8 sm:py-12">
          {children}
        </main>
      </div>
    </div>
  );
}
