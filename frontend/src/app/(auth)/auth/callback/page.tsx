"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, LoaderCircle, ShieldCheck } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { completeOidcAuthorization } from "@/lib/auth/oidc";

export default function OidcCallbackPage() {
  const { establishOidcSession } = useAuth();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const callbackCompletion = useRef<ReturnType<typeof completeOidcAuthorization> | null>(null);

  useEffect(() => {
    // The callback consumes its single-use state before awaiting token
    // exchange. React Strict Mode re-runs effects in development, so reuse the
    // first completion rather than treating the intentionally consumed state
    // as an invalid login in the second invocation.
    let cancelled = false;
    const completion = callbackCompletion.current ??= completeOidcAuthorization(window.location.search);
    void completion
      .then(({ session, returnTo }) => {
        if (cancelled) return;
        establishOidcSession(session);
        router.replace(returnTo);
      })
      .catch((caught) => {
        if (cancelled) return;
        setError(caught instanceof Error ? caught.message : "Không thể hoàn tất đăng nhập OIDC.");
      });
    return () => { cancelled = true; };
  }, [establishOidcSession, router]);

  return (
    <section className="rounded-2xl border border-border bg-card p-6 text-center shadow-sm" aria-live="polite">
      {error ? (
        <>
          <span className="mx-auto grid size-12 place-items-center rounded-2xl bg-destructive/10 text-destructive">
            <AlertTriangle className="size-6" />
          </span>
          <h1 className="mt-4 text-xl font-bold">Đăng nhập không thành công</h1>
          <p role="alert" className="mt-2 text-sm leading-6 text-muted-foreground">{error}</p>
          <Link href="/login" className="mt-5 inline-flex rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">
            Quay lại đăng nhập
          </Link>
        </>
      ) : (
        <>
          <span className="mx-auto grid size-12 place-items-center rounded-2xl bg-primary/10 text-primary">
            <ShieldCheck className="size-6" />
          </span>
          <h1 className="mt-4 text-xl font-bold">Đang xác minh phiên đăng nhập</h1>
          <p className="mt-2 text-sm text-muted-foreground">Kiểm tra state, PKCE và token từ Identity Provider.</p>
          <LoaderCircle className="mx-auto mt-5 size-5 animate-spin text-primary" aria-hidden="true" />
        </>
      )}
    </section>
  );
}
