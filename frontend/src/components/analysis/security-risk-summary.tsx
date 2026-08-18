import { ActionRiskPanel } from "@/components/analysis/action-risk-panel";
import { mapSecurityCaseViewModel, type SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type { SecurityScopeResponseV4 } from "@/types/generated/api-v4";

export function SecurityRiskSummary({
  result,
  mode = "simple",
}: {
  result: SecurityScopeResponseV4;
  mode?: SecurityPresentationMode;
}) {
  return <ActionRiskPanel viewModel={mapSecurityCaseViewModel(result)} mode={mode} />;
}
