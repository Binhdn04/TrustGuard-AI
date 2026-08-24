"use client";

import { useState } from "react";
import Link from "next/link";
import { AlertCircle, ArrowRight, ShieldCheck } from "lucide-react";

import { createOidcAuthorizationRequest, isOidcConfigured } from "@/lib/auth/oidc";

export default function RegisterPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const oidcConfigured = isOidcConfigured();

  const oidcSignup = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const authorizationUrl = await createOidcAuthorizationRequest("/", { screenHint: "signup" });
      window.location.assign(authorizationUrl);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Không thể bắt đầu đăng ký OIDC.");
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="space-y-2 text-center lg:text-left">
        <h2 className="text-3xl font-bold tracking-tight text-foreground">Tạo tài khoản mới</h2>
        <p className="text-muted-foreground">Đăng ký an toàn qua Identity Provider</p>
      </div>

      <div className="space-y-4 rounded-2xl border border-border bg-card/70 p-5">
        <div className="flex items-start gap-3">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
            <ShieldCheck className="size-5" />
          </span>
          <div>
            <p className="font-semibold">Tạo tài khoản qua Auth0</p>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">
              Auth0 xử lý email, mật khẩu và xác minh danh tính. Tài khoản mới luôn bắt đầu với quyền User.
            </p>
          </div>
        </div>
        {error && <p role="alert" className="flex gap-2 rounded-xl bg-destructive/10 p-3 text-sm text-destructive"><AlertCircle className="mt-0.5 size-4 shrink-0" />{error}</p>}
        <button
          type="button"
          disabled={isLoading || !oidcConfigured}
          onClick={() => void oidcSignup()}
          className="flex w-full items-center justify-center rounded-lg bg-primary px-4 py-2.5 font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
        >
          {isLoading ? "Đang chuyển hướng…" : "Tiếp tục đăng ký"} <ArrowRight className="ml-2 size-4" />
        </button>
        {!oidcConfigured && <p role="status" className="text-xs text-muted-foreground">OIDC chưa được cấu hình. Liên hệ quản trị viên hệ thống.</p>}
      </div>

      <p className="text-center text-sm text-muted-foreground">
        Đã có tài khoản?{" "}
        <Link href="/login" className="font-semibold text-primary hover:underline">
          Đăng nhập
        </Link>
      </p>
    </div>
  );
}
