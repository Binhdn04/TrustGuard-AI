"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";
import { AlertCircle, ArrowRight, ShieldAlert, ShieldCheck, UserCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { createOidcAuthorizationRequest, isOidcConfigured } from "@/lib/auth/oidc";

export default function LoginPage() {
  const { login } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const oidcConfigured = isOidcConfigured();
  const demoAuthEnabled = Boolean(
    process.env.NEXT_PUBLIC_DEMO_USER_TOKEN && process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN,
  );

  const mockLogin = (role: "user" | "security_admin") => {
    setIsLoading(true);
    setTimeout(() => {
      login({
        id: role === "user" ? "u_1" : "a_1",
        name: role === "user" ? "Người dùng thử nghiệm" : "Quản trị viên bảo mật",
        email: role === "user" ? "user@example.com" : "admin@aiprotect.vn",
        role: role,
      });
    }, 800);
  };

  const oidcLogin = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams(window.location.search);
      const authorizationUrl = await createOidcAuthorizationRequest(params.get("returnTo") ?? "/");
      window.location.assign(authorizationUrl);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không thể bắt đầu đăng nhập OIDC.");
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="space-y-2 text-center lg:text-left">
        <h2 className="text-3xl font-bold tracking-tight text-foreground">Chào mừng trở lại</h2>
        <p className="text-muted-foreground">Đăng nhập vào hệ thống AI PROTECT</p>
      </div>

      <div className="space-y-4 rounded-2xl border border-border bg-card/70 p-5">
        <div className="flex items-start gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
            <ShieldCheck className="size-5" />
          </span>
          <div>
            <p className="font-semibold">Đăng nhập qua Identity Provider</p>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">
              Phiên đăng nhập dùng Authorization Code + PKCE. Quyền truy cập cuối cùng luôn được backend xác minh.
            </p>
          </div>
        </div>
        {error && <p role="alert" className="flex gap-2 rounded-xl bg-destructive/10 p-3 text-sm text-destructive"><AlertCircle className="mt-0.5 size-4 shrink-0" />{error}</p>}
        <button
          type="button"
          disabled={isLoading || !oidcConfigured}
          onClick={() => void oidcLogin()}
          className="w-full flex items-center justify-center py-2.5 px-4 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
        >
          {isLoading ? "Đang chuyển hướng…" : "Tiếp tục đăng nhập"} <ArrowRight className="w-4 h-4 ml-2" />
        </button>
        {!oidcConfigured && !demoAuthEnabled && <p role="status" className="text-xs text-muted-foreground">OIDC chưa được cấu hình. Liên hệ quản trị viên hệ thống.</p>}
      </div>

      {demoAuthEnabled && <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t border-border" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">Đăng nhập demo MVP (bỏ qua mật khẩu)</span>
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
          <span className="text-sm font-medium">Quyền người dùng</span>
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
          <span className="text-sm font-medium">Quyền quản trị bảo mật</span>
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
