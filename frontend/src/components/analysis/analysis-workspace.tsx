"use client";

import { useEffect, useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";

import { CaseEmptyState } from "@/components/analysis/case-empty-state";
import { CaseWorkspace } from "@/components/analysis/case-workspace";
import { SecurityChatComposer } from "@/components/analysis/security-chat-composer";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useSecurityCase } from "@/lib/hooks/use-security-case";

export function AnalysisWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const [status, setStatus] = useState<"loading" | "pending" | "granted" | "denied" | "error">(
    api.getAccountLookupConsent ? "loading" : "granted",
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!api.getAccountLookupConsent) return;
    const load = api.getAccountLookupConsent();
    void load.then((value) => setStatus(value.status)).catch(() => {
      setError("Không thể tải lựa chọn quyền riêng tư."); setStatus("error");
    });
  }, [api]);
  const decide = async (granted: boolean) => {
    if (!api.decideAccountLookupConsent) return;
    setSaving(true); setError(null);
    try { setStatus((await api.decideAccountLookupConsent(granted)).status); }
    catch { setError("Không thể lưu lựa chọn. Vui lòng thử lại."); }
    finally { setSaving(false); }
  };
  const securityCase = useSecurityCase(api, {
    external_url_lookup: status === "granted",
    official_source_lookup: status === "granted",
  });

  if (status === "loading" || status === "error") return (
    <div className="grid min-h-80 place-items-center text-sm text-muted-foreground">
      {status === "loading" ? <span className="inline-flex items-center gap-2"><Loader2 className="size-4 animate-spin" />Đang tải quyền riêng tư</span> : <div role="alert">{error}<button type="button" onClick={() => window.location.reload()} className="ml-2 font-semibold text-primary">Thử lại</button></div>}
    </div>
  );

  if (status === "pending") return (
    <div className="mx-auto grid min-h-[28rem] max-w-xl place-items-center px-4">
      <section role="dialog" aria-modal="true" aria-labelledby="lookup-consent-title" className="rounded-2xl border border-border bg-card p-6 shadow-sm">
        <ShieldCheck className="size-8 text-primary" />
        <h1 id="lookup-consent-title" className="mt-4 text-xl font-semibold">Cho phép tra cứu bảo mật?</h1>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">Khi đồng ý, Agent có thể gửi URL và metadata cần thiết tới dịch vụ bảo mật bên ngoài, đồng thời tra cứu nguồn công khai để đối chiếu. Không gửi mật khẩu, OTP hoặc token.</p>
        <p className="mt-3 text-xs text-muted-foreground">Lựa chọn này áp dụng cho tài khoản của bạn ở các lần sau. Bạn có thể liên hệ hỗ trợ nếu cần thay đổi.</p>
        <div className="mt-6 flex flex-wrap gap-3"><button type="button" disabled={saving} onClick={() => void decide(true)} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-50">Đồng ý</button><button type="button" disabled={saving} onClick={() => void decide(false)} className="rounded-xl border border-border px-4 py-2 text-sm font-semibold disabled:opacity-50">Không đồng ý</button></div>
        {error && <p role="alert" className="mt-3 text-sm text-destructive">{error}</p>}
      </section>
    </div>
  );

  if (securityCase.state === "IDLE" && securityCase.turns.length === 0) {
    return (
      <CaseEmptyState
        composer={(
          <SecurityChatComposer
            onSubmit={securityCase.submit}
            busy={false}
            variant="intake"
          />
        )}
      />
    );
  }

  return (
    <CaseWorkspace
      turns={securityCase.turns}
      state={securityCase.state}
      transport={securityCase.transport}
      error={securityCase.error}
      recoveryAction={securityCase.recoveryAction}
      lifecycleEvents={securityCase.lifecycleEvents}
      progress={securityCase.progress}
      latest={securityCase.latest}
      busy={securityCase.busy}
      api={api}
      onSubmit={securityCase.submit}
      onRetry={securityCase.retry}
      onRecover={securityCase.recoverLatestTurn}
      onReset={securityCase.reset}
    />
  );
}
