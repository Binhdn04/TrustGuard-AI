import Link from "next/link";

import { cn } from "@/lib/utils";
import type { Role } from "@/lib/auth-context";
import type { SecurityCapabilitiesResponseV4 } from "@/types/generated/api-v4";

import { isWorkspaceRouteActive, workspaceNavigation } from "./workspace-navigation";

export function MobileNavigation({
  pathname,
  role,
  capabilities,
}: {
  pathname: string;
  role: Role;
  capabilities: SecurityCapabilitiesResponseV4 | null;
}) {
  const items = workspaceNavigation(role, capabilities).flatMap((group) => group.items);

  return (
    <nav
      aria-label="Điều hướng di động"
      className="fixed inset-x-3 bottom-3 z-40 flex items-center gap-1 overflow-x-auto rounded-2xl border border-border/80 bg-card/95 p-1.5 shadow-[0_18px_55px_rgba(15,23,42,0.22)] backdrop-blur-xl lg:hidden"
    >
      {items.map((item) => {
        const Icon = item.icon;
        const active = item.href ? isWorkspaceRouteActive(pathname, item.href) : false;
        if (!item.href) {
          return (
            <span
              key={item.label}
              aria-disabled="true"
              className="flex min-w-[68px] flex-1 flex-col items-center gap-1 rounded-xl px-2 py-2 text-[10px] font-semibold text-muted-foreground/50"
            >
              <Icon className="size-[18px]" aria-hidden="true" />
              {item.label}
            </span>
          );
        }
        return (
          <Link
            key={item.label}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex min-w-[68px] flex-1 flex-col items-center gap-1 rounded-xl px-2 py-2 text-[10px] font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              active ? "bg-primary/12 text-primary" : "text-muted-foreground",
            )}
          >
            <Icon className="size-[18px]" aria-hidden="true" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
