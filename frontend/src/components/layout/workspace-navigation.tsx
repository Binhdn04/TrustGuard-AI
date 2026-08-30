import Link from "next/link";
import type { ComponentType, SVGProps } from "react";
import { Archive, BadgeCheck, Plus, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";
import type { Role } from "@/lib/auth-context";
import type { SecurityCapabilitiesResponseV4 } from "@/types/generated/api-v4";

type Icon = ComponentType<SVGProps<SVGSVGElement>>;

export interface WorkspaceNavItem {
  label: string;
  mobileLabel?: string;
  description: string;
  href?: string;
  icon: Icon;
  pending?: boolean;
}

export interface WorkspaceNavGroup {
  label: string;
  items: WorkspaceNavItem[];
}

export function workspaceNavigation(
  role: Role,
  _capabilities: SecurityCapabilitiesResponseV4 | null,
): WorkspaceNavGroup[] {
  void _capabilities;
  const groups: WorkspaceNavGroup[] = [
    {
      label: "Không gian làm việc",
      items: [
        { label: "Kiểm tra", description: "Bắt đầu kiểm tra bảo mật", href: "/", icon: Plus },
        { label: "Lịch sử", description: "Các lần kiểm tra của bạn", href: "/history", icon: Archive },
      ],
    },
  ];

  if (role !== "security_admin") return groups;

  const adminItems: WorkspaceNavItem[] = [
    { label: "Duyệt bảo mật", mobileLabel: "Duyệt", description: "Báo cáo và khiếu nại", href: "/admin/review", icon: BadgeCheck },
    { label: "Tin cậy & chặn", mobileLabel: "Tin cậy", description: "Ngoại lệ và domain chặn", href: "/admin/trust", icon: ShieldCheck },
  ];
  groups.push({ label: "Quản trị", items: adminItems });
  return groups;
}

export function isWorkspaceRouteActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === href;
  if (href === "/admin/review") return pathname === href;
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function WorkspaceNavigation({
  pathname,
  role,
  capabilities,
  className,
}: {
  pathname: string;
  role: Role;
  capabilities: SecurityCapabilitiesResponseV4 | null;
  className?: string;
}) {
  return (
    <nav aria-label="Điều hướng workspace" className={cn("space-y-7", className)}>
      {workspaceNavigation(role, capabilities).map((group) => (
        <div key={group.label}>
          <p className="px-3 text-[10px] font-bold uppercase tracking-[0.2em] text-muted-foreground">{group.label}</p>
          <div className="mt-2 space-y-1">
            {group.items.map((item) => {
              const Icon = item.icon;
              if (!item.href) {
                return (
                  <div
                    key={item.label}
                    aria-disabled="true"
                    className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-muted-foreground/65"
                  >
                    <Icon className="size-[18px]" aria-hidden="true" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-medium">{item.label}</span>
                      <span className="block truncate text-[11px]">{item.description}</span>
                    </span>
                    <span className="rounded-md border border-border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide">Soon</span>
                  </div>
                );
              }
              const active = isWorkspaceRouteActive(pathname, item.href);
              return (
                <Link
                  key={item.label}
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "group flex items-center gap-3 rounded-xl border px-3 py-2.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    active
                      ? "border-primary/20 bg-primary/10 text-foreground"
                      : "border-transparent text-muted-foreground hover:border-border hover:bg-muted/60 hover:text-foreground",
                  )}
                >
                  <Icon className={cn("size-[18px]", active && "text-primary")} aria-hidden="true" />
                  <span className="min-w-0">
                    <span className="block text-sm font-semibold">{item.label}</span>
                    <span className="block truncate text-[11px] text-muted-foreground">{item.description}</span>
                  </span>
                </Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}
