import { CaseDetail } from "@/components/cases/case-detail";

export default async function SecurityCasePage({
  params,
}: {
  params: Promise<{ analysisId: string }>;
}) {
  const { analysisId } = await params;
  return <CaseDetail analysisId={analysisId} />;
}
