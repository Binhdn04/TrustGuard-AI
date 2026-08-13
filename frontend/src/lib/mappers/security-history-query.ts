import type { SecurityAnalysisPageQuery } from "@/lib/api/security-analysis-api.types";
import type { SecurityRiskV4, SecurityScopeDecisionV4 } from "@/types/generated/api-v4";

export const SECURITY_HISTORY_PAGE_SIZE = 10;

export interface SecurityHistoryQuery {
  q: string;
  scopeDecision: SecurityScopeDecisionV4 | null;
  risk: SecurityRiskV4 | null;
  page: number;
}

const risks = new Set<SecurityRiskV4>([
  "SAFE",
  "LOW_RISK",
  "SUSPICIOUS",
  "HIGH_RISK",
  "MALICIOUS",
  "INSUFFICIENT_EVIDENCE",
]);
const scopeDecisions = new Set<SecurityScopeDecisionV4>([
  "IN_SCOPE",
  "NEED_MORE_INFO",
  "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
]);

function first(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? "" : value ?? "";
}

export function parseSecurityHistoryQuery(
  searchParams: Record<string, string | string[] | undefined>,
): SecurityHistoryQuery {
  const riskValue = first(searchParams.risk);
  const scopeValue = first(searchParams.scope);
  const pageValue = Number.parseInt(first(searchParams.page), 10);
  return {
    q: first(searchParams.q).trim().slice(0, 200),
    scopeDecision: scopeDecisions.has(scopeValue as SecurityScopeDecisionV4)
      ? scopeValue as SecurityScopeDecisionV4
      : null,
    risk: risks.has(riskValue as SecurityRiskV4) ? riskValue as SecurityRiskV4 : null,
    page: Number.isFinite(pageValue) && pageValue > 0 ? pageValue : 1,
  };
}

export function toSecurityAnalysisPageQuery(query: SecurityHistoryQuery): SecurityAnalysisPageQuery {
  return {
    limit: SECURITY_HISTORY_PAGE_SIZE,
    offset: (query.page - 1) * SECURITY_HISTORY_PAGE_SIZE,
    ...(query.q ? { q: query.q } : {}),
    ...(query.scopeDecision ? { scope_decision: query.scopeDecision } : {}),
    ...(query.risk ? { risk: query.risk } : {}),
  };
}

export function securityHistoryHref(query: SecurityHistoryQuery): string {
  const params = new URLSearchParams();
  if (query.q) params.set("q", query.q);
  if (query.scopeDecision) params.set("scope", query.scopeDecision);
  if (query.risk) params.set("risk", query.risk);
  if (query.page > 1) params.set("page", String(query.page));
  const search = params.toString();
  return search ? `/history?${search}` : "/history";
}
