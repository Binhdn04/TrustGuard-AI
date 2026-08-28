"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, ChevronDown, FileSearch, RotateCcw, ShieldCheck } from "lucide-react";

import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { useAccountPreferences } from "@/lib/account-preferences-context";
import type { SecurityCaseState, SecurityCaseTurn } from "@/lib/hooks/use-security-case";
import {
  mapSecurityCaseViewModel,
  type SecurityCaseViewModel,
  type SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import { cn } from "@/lib/utils";
import { statusLabel } from "@/lib/presentation/security-labels";
import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityAnalysisEventV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";
import type { SecurityProgressViewModel } from "@/lib/security-progress";

import { ActionRiskPanel, SimpleRiskTechnicalDetails } from "./action-risk-panel";
import { AnalysisAppealForm } from "./analysis-appeal-form";
import { AnalysisReportForm } from "./analysis-report-form";
import { CaseSignalMap } from "./case-signal-map";
import { ConversationPanel } from "./conversation-panel";
import { EvidenceDeck } from "./evidence-deck";
import { DomainIdentitySummary } from "./domain-identity-summary";
import { InvestigationTimelineV4 } from "./investigation-timeline-v4";
import { OfficialVerificationPanel } from "./official-verification-panel";
import { PageCapturePanel } from "./page-capture-panel";
import { SimpleAnalystToggle } from "./simple-analyst-toggle";

type MobilePanel = "conversation" | "investigation" | "action";

const analystPanels: Array<{ id: MobilePanel; label: string }> = [
  { id: "conversation", label: "Trò chuyện" },
  { id: "investigation", label: "Điều tra" },
  { id: "action", label: "Hành động" },
];

const userPanels: Array<{ id: MobilePanel; label: string }> = [
  { id: "conversation", label: "Trò chuyện" },
  { id: "action", label: "Kết quả" },
];

function InvestigationPanel({
  viewModel,
  latest,
  busy,
  mode,
}: {
  viewModel: SecurityCaseViewModel | null;
  latest: SecurityScopeResponseV4 | null;
  busy: boolean;
  mode: SecurityPresentationMode;
}) {
  return (
    <section aria-labelledby="investigation-heading" className="case-panel min-h-[36rem] overflow-hidden">
      <header className="border-b border-border/70 px-4 py-3.5">
        <p className="micro-label">02 / Điều tra</p>
        <h2 id="investigation-heading" className="mt-1 text-sm font-semibold">Tín hiệu và bằng chứng</h2>
      </header>
      <div className="space-y-6 p-4">
        {busy && (
          <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
            <p className="flex items-center gap-2 text-sm font-semibold"><Activity className="size-4 text-primary" />Đang chờ kết quả điều tra</p>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              Chỉ hiển thị bước và bằng chứng sau khi API trả về; không mô phỏng DNS, chuyển hướng hoặc lệnh gọi nhà cung cấp.
            </p>
          </div>
        )}
        {!busy && viewModel && latest?.scope_decision === "IN_SCOPE" && (
          <>
            <CaseSignalMap nodes={viewModel.signalNodes} edges={viewModel.signalEdges} mode={mode} />
            <InvestigationTimelineV4
              lifecycle={viewModel.lifecycle}
              steps={viewModel.steps}
              errors={viewModel.errors}
              mode={mode}
            />
            <EvidenceDeck evidence={viewModel.evidence} mode={mode} />
          </>
        )}
        {!busy && latest?.scope_decision !== "IN_SCOPE" && (
          <div className="rounded-xl border border-dashed border-border p-5 text-center">
            <FileSearch className="mx-auto size-5 text-muted-foreground" />
            <p className="mt-2 text-sm font-semibold">Chưa mở điều tra</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Trường hợp cần nằm trong phạm vi và đủ ngữ cảnh trước khi có kết quả điều tra.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}

function ActionPanel({
  latest,
  viewModel,
  busy,
  mode,
  api,
}: {
  latest: SecurityScopeResponseV4 | null;
  viewModel: SecurityCaseViewModel | null;
  busy: boolean;
  mode: SecurityPresentationMode;
  api: SecurityAnalysisApi;
}) {
  const completed = latest?.scope_decision === "IN_SCOPE" && latest.status === "completed" && latest.risk
    ? viewModel
    : null;
  return (
    <section aria-labelledby="action-heading" className="case-panel min-h-[36rem] overflow-hidden">
      <header className="border-b border-border/70 px-4 py-3.5">
        {mode === "analyst" && <p className="micro-label">03 / Hành động</p>}
        <h2 id="action-heading" className={mode === "simple" ? "text-sm font-semibold" : "mt-1 text-sm font-semibold"}>
          {mode === "simple" ? "Kết luận và hướng dẫn" : "Quyết định và bước tiếp theo"}
        </h2>
      </header>
      <div className="space-y-4 p-4">
        {completed ? (
          <>
            <ActionRiskPanel
              viewModel={completed}
              mode={mode}
              showSimpleTechnicalDetails={mode !== "simple"}
            />
            {mode === "simple" && <DomainIdentitySummary viewModel={completed} mode="simple" />}
            {mode === "simple" && (
              <PageCapturePanel
                analysisId={latest!.analysis_id}
                urls={completed.context?.urls ?? []}
                api={api}
              />
            )}
            {mode === "simple" ? (
              <details
                key={`${latest!.analysis_id}:${latest!.conversation_version}`}
                className="group/result overflow-hidden rounded-2xl border border-primary/25 bg-background/55 shadow-sm"
              >
                <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3.5 text-sm font-semibold text-primary hover:bg-primary/5">
                  <span>Xem kết quả chi tiết</span>
                  <ChevronDown className="size-4 transition-transform group-open/result:rotate-180" aria-hidden="true" />
                </summary>
                <div className="space-y-4 border-t border-border/70 p-4">
                  <SimpleRiskTechnicalDetails viewModel={completed} />
                  <details className="group/checks rounded-2xl border border-border bg-background/45">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold">
                      Đã kiểm tra những gì?
                      <ChevronDown className="size-4 transition-transform group-open/checks:rotate-180" aria-hidden="true" />
                    </summary>
                    <div className="space-y-5 border-t border-border/70 p-4">
                      <InvestigationTimelineV4 lifecycle={completed.lifecycle} steps={completed.steps} errors={completed.errors} mode="simple" />
                      <EvidenceDeck evidence={completed.evidence} mode="simple" />
                    </div>
                  </details>
                  <details className="group/report rounded-2xl border border-border bg-background/45">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold">
                      Báo cáo hoặc yêu cầu xem xét
                      <ChevronDown className="size-4 transition-transform group-open/report:rotate-180" aria-hidden="true" />
                    </summary>
                    <div className="space-y-4 border-t border-border/70 p-4">
                      <AnalysisReportForm analysisId={latest!.analysis_id} securityApi={api} />
                      <AnalysisAppealForm analysisId={latest!.analysis_id} securityApi={api} />
                    </div>
                  </details>
                </div>
              </details>
            ) : (
              <>
                <DomainIdentitySummary viewModel={completed} mode="analyst" />
                <OfficialVerificationPanel viewModel={completed} mode="analyst" />
                <PageCapturePanel
                  analysisId={latest!.analysis_id}
                  urls={completed.context?.urls ?? []}
                  api={api}
                />
                <AnalysisReportForm analysisId={latest!.analysis_id} securityApi={api} />
                <AnalysisAppealForm analysisId={latest!.analysis_id} securityApi={api} />
              </>
            )}
          </>
        ) : (
          <div className="rounded-xl border border-dashed border-border p-5 text-center">
            <ShieldCheck className="mx-auto size-5 text-muted-foreground" />
            <p className="mt-2 text-sm font-semibold">{busy ? "Đang chờ kết quả" : "Chưa có hướng dẫn"}</p>
            {mode === "analyst" && (
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Frontend không tự tính kết luận, điểm số hoặc hành động khi API chưa trả kết quả.
              </p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export function CaseWorkspace({
  turns,
  state,
  transport,
  error,
  lifecycleEvents,
  progress,
  latest,
  busy,
  api,
  onSubmit,
  onRetry,
  onReset,
}: {
  turns: SecurityCaseTurn[];
  state: SecurityCaseState;
  transport: AnalysisTransportState;
  error: string | null;
  lifecycleEvents: SecurityAnalysisEventV4[];
  progress: SecurityProgressViewModel;
  latest: SecurityScopeResponseV4 | null;
  busy: boolean;
  api: SecurityAnalysisApi;
  onSubmit(message: string): void;
  onRetry(): void;
  onReset(): void;
}) {
  const { preferences } = useAccountPreferences();
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>("conversation");
  const [mode, setMode] = useState<SecurityPresentationMode>("simple");
  useEffect(() => {
    // Presentation preference never changes the analysis request or result.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMode(preferences.defaultPresentation);
  }, [preferences.defaultPresentation]);
  const analysisLabel = latest?.analysis_id ? latest.analysis_id.slice(0, 8) : "đang chờ";
  const viewModel = useMemo(
    () => latest ? mapSecurityCaseViewModel(latest, lifecycleEvents) : null,
    [latest, lifecycleEvents],
  );
  const analysisBusy = state === "RUNNING" || state === "PROVISIONAL_WARNING";
  const panels = mode === "simple" ? userPanels : analystPanels;

  return (
    <div className="space-y-4">
      <header className="flex flex-col justify-between gap-4 border-b border-border/70 pb-4 sm:flex-row sm:items-end">
        <div>
          {mode === "analyst" && <p className="micro-label text-primary">TRƯỜNG HỢP ĐANG MỞ / {analysisLabel}</p>}
          <h1 className={cn("text-2xl font-semibold tracking-[-0.025em] sm:text-3xl", mode === "analyst" && "mt-2")}>
            {mode === "simple" ? "Trợ lý an toàn số" : "Không gian điều tra bảo mật"}
          </h1>
          {mode === "analyst" && (
            <p className="mt-1 text-sm text-muted-foreground">
              {latest ? `${statusLabel(latest.status)} · ${statusLabel(latest.scope_decision)}` : "Đang tạo trường hợp từ nội dung tiếp nhận"}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SimpleAnalystToggle
            mode={mode}
            onChange={(nextMode) => {
              setMode(nextMode);
              if (nextMode === "simple" && mobilePanel === "investigation") setMobilePanel("action");
            }}
          />
          <button type="button" onClick={onReset} className="inline-flex w-fit items-center gap-2 rounded-xl border border-border bg-card px-3.5 py-2 text-xs font-semibold hover:bg-muted">
            <RotateCcw className="size-3.5" />Bắt đầu trường hợp mới
          </button>
        </div>
      </header>

      <div className={cn("grid rounded-xl border border-border bg-card p-1 lg:hidden", mode === "simple" ? "grid-cols-2" : "grid-cols-3")} role="tablist" aria-label="Khu vực trường hợp">
        {panels.map((panel) => (
          <button
            key={panel.id}
            type="button"
            role="tab"
            aria-selected={mobilePanel === panel.id}
            onClick={() => setMobilePanel(panel.id)}
            className={cn("rounded-lg px-2 py-2 text-xs font-semibold", mobilePanel === panel.id ? "bg-primary/10 text-primary" : "text-muted-foreground")}
          >
            {panel.label}
          </button>
        ))}
      </div>

      <div className={cn(
        "grid gap-4",
        mode === "simple"
          ? "lg:grid-cols-[minmax(25rem,1.35fr)_minmax(22rem,0.75fr)]"
          : "lg:grid-cols-[minmax(19rem,0.78fr)_minmax(23rem,1.12fr)_minmax(20rem,0.9fr)]",
      )}>
        <div className={cn(mobilePanel !== "conversation" && "hidden", "lg:block")}>
          <ConversationPanel
            turns={turns}
            state={state}
            transport={transport}
            error={error}
            busy={busy}
            mode={mode}
            progress={progress}
            followUp={state === "NEED_MORE_INFO" ? latest?.follow_up_question : null}
            onSubmit={onSubmit}
            onRetry={onRetry}
          />
        </div>
        {mode === "analyst" && (
          <div className={cn(mobilePanel !== "investigation" && "hidden", "lg:block")}>
            <InvestigationPanel viewModel={viewModel} latest={latest} busy={analysisBusy} mode={mode} />
          </div>
        )}
        <div className={cn(mobilePanel !== "action" && "hidden", "lg:block")}>
          <ActionPanel latest={latest} viewModel={viewModel} busy={analysisBusy} mode={mode} api={api} />
        </div>
      </div>
    </div>
  );
}
