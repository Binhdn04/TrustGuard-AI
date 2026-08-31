"use client";

import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { avatarToneClass, useAccountPreferences } from "@/lib/account-preferences-context";
import { ShieldCheck, User, Settings, LogOut, LayoutDashboard } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";
import { cn } from "@/lib/utils";

export function UserMenu() {
  const { user, logout } = useAuth();
  const { preferences } = useAccountPreferences();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setIsOpen(false);
    }
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
    };
  }, []);

  if (!user) return null;

  const displayName = preferences.displayName || user.name;
  const reduceMotion = preferences.motion === "reduced";

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        aria-label="Mở menu tài khoản"
        aria-haspopup="menu"
        aria-expanded={isOpen}
        className={cn("flex size-10 items-center justify-center rounded-full border transition-colors hover:brightness-95", avatarToneClass[preferences.avatarTone])}
      >
        <span className="text-sm font-bold uppercase">{displayName.charAt(0)}</span>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={reduceMotion ? false : { opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: reduceMotion ? 0 : 0.2 }}
            role="menu"
            aria-label="Tài khoản"
            className="absolute right-0 z-50 mt-2 w-72 overflow-hidden rounded-xl border border-border bg-card shadow-xl backdrop-blur-xl"
          >
            <div className="p-4 border-b border-border bg-muted/50">
              <p className="font-semibold text-foreground truncate">{displayName}</p>
              <p className="text-xs text-muted-foreground truncate">{user.email}</p>
              <div className="mt-2 inline-flex items-center px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider bg-primary/20 text-primary">
                {user.role === "security_admin" ? (
                  <><ShieldCheck className="w-3 h-3 mr-1" /> Quản trị bảo mật</>
                ) : (
                  <><User className="w-3 h-3 mr-1" /> Người dùng</>
                )}
              </div>
            </div>

            <div className="p-2 space-y-1">
              {user.role === "security_admin" && (
                <Link
                  href="/admin"
                  role="menuitem"
                  className="flex items-center px-3 py-2 text-sm rounded-md text-foreground hover:bg-secondary transition-colors"
                  onClick={() => setIsOpen(false)}
                >
                  <LayoutDashboard className="w-4 h-4 mr-3 text-muted-foreground" />
                  Khu vực quản trị
                </Link>
              )}
              
              <Link
                href="/profile"
                role="menuitem"
                className="flex w-full items-center rounded-md px-3 py-2 text-sm text-foreground transition-colors hover:bg-secondary"
                onClick={() => setIsOpen(false)}
              >
                <User className="w-4 h-4 mr-3 text-muted-foreground" />
                Hồ sơ cá nhân
              </Link>
              
              <Link
                href="/settings"
                role="menuitem"
                className="flex w-full items-center rounded-md px-3 py-2 text-sm text-foreground transition-colors hover:bg-secondary"
                onClick={() => setIsOpen(false)}
              >
                <Settings className="w-4 h-4 mr-3 text-muted-foreground" />
                Cài đặt
              </Link>
            </div>

            <div className="p-2 border-t border-border bg-muted/30">
              <button
                role="menuitem"
                onClick={() => {
                  setIsOpen(false);
                  logout();
                }}
                className="w-full flex items-center px-3 py-2 text-sm rounded-md text-destructive hover:bg-destructive/10 transition-colors"
              >
                <LogOut className="w-4 h-4 mr-3" />
                Đăng xuất
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
