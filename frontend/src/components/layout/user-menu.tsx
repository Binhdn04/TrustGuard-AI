"use client";

import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { ShieldCheck, User, Settings, LogOut, LayoutDashboard } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";

export function UserMenu() {
  const { user, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  if (!user) return null;

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-center w-10 h-10 rounded-full bg-primary/10 text-primary hover:bg-primary/20 transition-colors border border-primary/20"
      >
        <span className="font-bold text-sm uppercase">{user.name.charAt(0)}</span>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute right-0 mt-2 w-64 rounded-xl border border-border bg-card shadow-xl overflow-hidden z-50 backdrop-blur-xl"
          >
            {/* Header info */}
            <div className="p-4 border-b border-border bg-muted/50">
              <p className="font-semibold text-foreground truncate">{user.name}</p>
              <p className="text-xs text-muted-foreground truncate">{user.email}</p>
              <div className="mt-2 inline-flex items-center px-2 py-1 rounded text-[10px] font-semibold uppercase tracking-wider bg-primary/20 text-primary">
                {user.role === "security_admin" ? (
                  <><ShieldCheck className="w-3 h-3 mr-1" /> Security Admin</>
                ) : (
                  <><User className="w-3 h-3 mr-1" /> User</>
                )}
              </div>
            </div>

            <div className="p-2 space-y-1">
              {user.role === "security_admin" && (
                <Link
                  href="/admin"
                  className="flex items-center px-3 py-2 text-sm rounded-md text-foreground hover:bg-secondary transition-colors"
                  onClick={() => setIsOpen(false)}
                >
                  <LayoutDashboard className="w-4 h-4 mr-3 text-muted-foreground" />
                  Admin Dashboard
                </Link>
              )}
              
              <button
                className="w-full flex items-center px-3 py-2 text-sm rounded-md text-foreground hover:bg-secondary transition-colors"
              >
                <User className="w-4 h-4 mr-3 text-muted-foreground" />
                Hồ sơ cá nhân
              </button>
              
              <button
                className="w-full flex items-center px-3 py-2 text-sm rounded-md text-foreground hover:bg-secondary transition-colors"
              >
                <Settings className="w-4 h-4 mr-3 text-muted-foreground" />
                Cài đặt
              </button>
            </div>

            <div className="p-2 border-t border-border bg-muted/30">
              <button
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
