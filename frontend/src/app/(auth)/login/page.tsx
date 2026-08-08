"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";
import { ArrowRight, Lock, Mail, ShieldAlert, UserCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export default function LoginPage() {
  const { login } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const oidcLoginUrl = process.env.NEXT_PUBLIC_OIDC_LOGIN_URL;
  const demoAuthEnabled = Boolean(
    process.env.NEXT_PUBLIC_DEMO_USER_TOKEN && process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN,
  );

  const mockLogin = (role: "user" | "security_admin") => {
    setIsLoading(true);
    setTimeout(() => {
      login({
        id: role === "user" ? "u_1" : "a_1",
        name: role === "user" ? "Người dùng Test" : "Security Admin",
        email: role === "user" ? "user@example.com" : "admin@aiprotect.vn",
        role: role,
      });
    }, 800);
  };

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="space-y-2 text-center lg:text-left">
        <h2 className="text-3xl font-bold tracking-tight text-foreground">Chào mừng trở lại</h2>
        <p className="text-muted-foreground">Đăng nhập vào hệ thống AI PROTECT</p>
      </div>

      <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground">Email</label>
          <div className="relative">
            <Mail className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
            <input 
              type="email" 
              placeholder="name@example.com"
              className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all disabled:opacity-50"
              disabled={isLoading}
            />
          </div>
        </div>
        
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-foreground">Mật khẩu</label>
            <Link href="#" className="text-xs text-primary hover:underline">Quên mật khẩu?</Link>
          </div>
          <div className="relative">
            <Lock className="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
            <input 
              type="password" 
              placeholder="••••••••"
              className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all disabled:opacity-50"
              disabled={isLoading}
            />
          </div>
        </div>

        <button
          type="button"
          disabled={isLoading || !oidcLoginUrl}
          onClick={() => {
            if (oidcLoginUrl) window.location.assign(oidcLoginUrl);
          }}
          className="w-full flex items-center justify-center py-2.5 px-4 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          Đăng nhập <ArrowRight className="w-4 h-4 ml-2" />
        </button>
      </form>

      {demoAuthEnabled && <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t border-border" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">Demo MVP Login (Bỏ qua mật khẩu)</span>
        </div>
      </div>}

      {demoAuthEnabled && <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <button
          onClick={() => mockLogin("user")}
          disabled={isLoading}
          className={cn(
            "flex items-center justify-center p-3 border rounded-lg transition-all",
            "border-primary/30 bg-primary/5 hover:bg-primary/10 text-foreground"
          )}
        >
          <UserCheck className="w-5 h-5 mr-2 text-primary" />
          <span className="text-sm font-medium">Quyền User</span>
        </button>
        <button
          onClick={() => mockLogin("security_admin")}
          disabled={isLoading}
          className={cn(
            "flex items-center justify-center p-3 border rounded-lg transition-all",
            "border-amber-500/30 bg-amber-500/5 hover:bg-amber-500/10 text-foreground"
          )}
        >
          <ShieldAlert className="w-5 h-5 mr-2 text-amber-500" />
          <span className="text-sm font-medium">Quyền Admin</span>
        </button>
      </div>}

      <p className="text-center text-sm text-muted-foreground">
        Chưa có tài khoản?{" "}
        <Link href="/register" className="font-semibold text-primary hover:underline">
          Đăng ký ngay
        </Link>
      </p>
    </div>
  );
}
