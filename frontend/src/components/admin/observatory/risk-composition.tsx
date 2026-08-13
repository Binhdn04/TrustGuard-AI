import type { SecurityRiskV4, SecurityThreatIntelligenceV4 } from "@/types/generated/api-v4";

const riskOrder: SecurityRiskV4[] = ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "SAFE", "INSUFFICIENT_EVIDENCE"];

export function composeRiskCounts(items: SecurityThreatIntelligenceV4[]) {
  const counts = new Map<SecurityRiskV4, number>();
  items.forEach((item) => Object.entries(item.risk_distribution).forEach(([risk, count]) => counts.set(risk as SecurityRiskV4, (counts.get(risk as SecurityRiskV4) ?? 0) + (count ?? 0))));
  const total = [...counts.values()].reduce((sum, count) => sum + count, 0);
  return riskOrder.map((risk) => ({ risk, count: counts.get(risk) ?? 0, share: total ? ((counts.get(risk) ?? 0) / total) * 100 : 0 })).filter((item) => item.count > 0);
}

export function RiskComposition({ threats, threatTotal, memoryTotal, loading, error }: {
  threats: SecurityThreatIntelligenceV4[];
  threatTotal: number;
  memoryTotal: number | null;
  loading: boolean;
  error: string | null;
}) {
  const complete = threats.length === threatTotal;
  const composition = complete ? composeRiskCounts(threats) : [];
  const total = composition.reduce((sum, item) => sum + item.count, 0);
  return (
    <section aria-labelledby="risk-composition-heading" className="case-panel p-5">
      <p className="micro-label">RISK COMPOSITION</p>
      <h2 id="risk-composition-heading" className="mt-1 text-lg font-semibold">Returned distribution counts</h2>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">Cộng trực tiếp risk distributions của toàn bộ threat categories trả về.</p>
      {loading && <p role="status" className="py-8 text-sm text-muted-foreground">Đang tải composition…</p>}
      {error && !loading && <p role="alert" className="mt-4 text-sm text-rose-800 dark:text-rose-200">{error}</p>}
      {!loading && !error && !complete && <p role="alert" className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">API page chưa bao phủ đủ {threatTotal} threat categories; không hiển thị composition chưa đầy đủ.</p>}
      {!loading && !error && complete && total > 0 && <div className="mt-5 space-y-3">{composition.map((item) => <div key={item.risk}><div className="mb-1 flex justify-between text-[11px]"><span className="font-mono font-semibold">{item.risk}</span><span>{item.count} · {item.share.toFixed(1)}%</span></div><div className="h-2 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary" style={{ width: `${item.share}%` }} /></div></div>)}</div>}
      {!loading && !error && complete && total === 0 && <p className="mt-4 text-sm text-muted-foreground">Không có distribution count.</p>}
      <dl className="mt-5 grid grid-cols-2 gap-3 border-t border-border/70 pt-4 text-xs"><div><dt className="text-muted-foreground">Distribution total</dt><dd className="mt-1 text-xl font-bold">{complete ? total : "—"}</dd></div><div><dt className="text-muted-foreground">Security Memory records</dt><dd className="mt-1 text-xl font-bold">{memoryTotal ?? "—"}</dd></div></dl>
    </section>
  );
}
