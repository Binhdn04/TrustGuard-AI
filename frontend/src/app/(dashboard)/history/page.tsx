import { CaseLibrary } from "@/components/cases/case-library";
import { parseSecurityHistoryQuery } from "@/lib/mappers/security-history-query";

export default async function HistoryPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const query = parseSecurityHistoryQuery(await searchParams);
  return <CaseLibrary key={`${query.q}:${query.scopeDecision}:${query.risk}:${query.page}`} initialQuery={query} />;
}
