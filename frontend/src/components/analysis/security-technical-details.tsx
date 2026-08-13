import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

export function SecurityTechnicalDetails({ result }: { result: SecurityScopeResponseV4 }) {
  return (
    <details className="rounded-2xl border border-border bg-card p-5">
      <summary className="cursor-pointer font-semibold">Chi tiết kỹ thuật và bằng chứng</summary>
      <div className="mt-4 space-y-5 text-sm">
        {result.security_context && <dl className="grid gap-3 sm:grid-cols-2"><div><dt className="text-xs text-muted-foreground">Kịch bản</dt><dd className="font-medium">{result.security_context.scenario}</dd></div><div><dt className="text-xs text-muted-foreground">Hành động được yêu cầu</dt><dd className="font-medium">{result.security_context.requested_action ?? "Chưa rõ"}</dd></div><div><dt className="text-xs text-muted-foreground">Thực thể tự nhận</dt><dd className="font-medium">{result.security_context.claimed_entity ?? "Chưa rõ"}</dd></div><div><dt className="text-xs text-muted-foreground">Policy</dt><dd className="font-mono text-xs">{result.policy_version ?? "—"}</dd></div></dl>}
        <div><h3 className="font-semibold">Bằng chứng ({result.evidence.length})</h3><ul className="mt-2 space-y-2">{result.evidence.map((item) => <li key={item.evidence_ref} className="rounded-xl bg-muted/50 p-3"><p className="font-medium">{item.description}</p><p className="mt-1 break-all text-xs text-muted-foreground">{item.source} · {item.signal} · {item.evidence_ref}</p></li>)}</ul>{result.evidence.length === 0 && <p className="mt-2 text-muted-foreground">Chưa có bằng chứng kỹ thuật.</p>}</div>
        <div><h3 className="font-semibold">Các bước điều tra</h3><ol className="mt-2 space-y-1 text-xs text-muted-foreground">{result.investigation_plan.map((step) => <li key={step.step_id}>{step.status} · {step.tool} · {step.reason_code}</li>)}</ol></div>
      </div>
    </details>
  );
}
