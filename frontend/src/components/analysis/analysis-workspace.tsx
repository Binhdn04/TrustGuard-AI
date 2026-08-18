"use client";

import { CaseEmptyState } from "@/components/analysis/case-empty-state";
import { CaseWorkspace } from "@/components/analysis/case-workspace";
import { SecurityChatComposer } from "@/components/analysis/security-chat-composer";
import { getSecurityAnalysisApi } from "@/lib/api/security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useSecurityCase } from "@/lib/hooks/use-security-case";

export function AnalysisWorkspace({ api = getSecurityAnalysisApi() }: { api?: SecurityAnalysisApi }) {
  const securityCase = useSecurityCase(api);

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
      lifecycleEvents={securityCase.lifecycleEvents}
      latest={securityCase.latest}
      busy={securityCase.busy}
      api={api}
      onSubmit={securityCase.submit}
      onRetry={securityCase.retry}
      onReset={securityCase.reset}
    />
  );
}
