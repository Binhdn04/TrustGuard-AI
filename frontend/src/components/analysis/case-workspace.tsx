"use client";

import { useMemo, useState } from "react";
import { Activity, Bot, ChevronDown, CircleHelp, FileSearch, RotateCcw, ShieldCheck } from "lucide-react";

import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityCaseState, SecurityCaseTurn } from "@/lib/hooks/use-security-case";
import {
  mapSecurityCaseViewModel,
  type SecurityCaseViewModel,
  type SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import { cn } from "@/lib/utils";
import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityAnalysisEventV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

import { ActionRiskPanel } from "./action-risk-panel";
import { AnalysisAppealForm } from "./analysis-appeal-form";
import { AnalysisLimitations } from "./analysis-limitations";
import { AnalysisReportForm } from "./analysis-report-form";
import { CaseSignalMap } from "./case-signal-map";
import { ConversationPanel } from "./conversation-panel";
import { EvidenceDeck } from "./evidence-deck";
import { InvestigationTimelineV4 } from "./investigation-timeline-v4";
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
        <p className="micro-label">02 / Investigation</p>
        <h2 id="investigation-heading" className="mt-1 text-sm font-semibold">Signals & evidence</h2>
      </header>
      <div className="space-y-6 p-4">
        {busy && (
          <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
            <p className="flex items-center gap-2 text-sm font-semibold"><Activity className="size-4 text-primary" />Đang chờ kết quả điều tra</p>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              Chỉ hiển thị step và evidence sau khi API trả về; không mô phỏng DNS, redirect hoặc provider call.
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
            <AnalysisLimitations limitations={latest.limitations} />
          </>
        )}
        {!busy && latest?.scope_decision !== "IN_SCOPE" && (
          <div className="rounded-xl border border-dashed border-border p-5 text-center">
            <FileSearch className="mx-auto size-5 text-muted-foreground" />
            <p className="mt-2 text-sm font-semibold">Chưa mở investigation</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Case cần nằm trong phạm vi và đủ context trước khi có investigation output.
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
  const reasons = completed?.assistant?.topReasons.slice(0, 3) ?? [];
  const uncertainties = completed?.assistant?.uncertainties.slice(0, 3) ?? [];
  return (
    <section aria-labelledby="action-heading" className="case-panel min-h-[36rem] overflow-hidden">
      <header className="border-b border-border/70 px-4 py-3.5">
        <p className="micro-label">{mode === "simple" ? "02 / Kết quả" : "03 / Action"}</p>
        <h2 id="action-heading" className="mt-1 text-sm font-semibold">
          {mode === "simple" ? "Kết luận và hướng dẫn" : "Decision & next steps"}
        </h2>
      </header>
      <div className="space-y-4 p-4">
        {completed ? (
          <>
            <ActionRiskPanel viewModel={completed} mode={mode} />
            {mode === "simple" && reasons.length > 0 && (
              <section aria-labelledby="agent-reasons-heading" className="rounded-2xl border border-primary/20 bg-primary/5 p-4">
                <div className="flex items-center gap-2">
                  <span className="grid size-8 place-items-center rounded-xl bg-primary/10 text-primary"><Bot className="size-4" aria-hidden="true" /></span>
                  <h3 id="agent-reasons-heading" className="text-sm font-semibold">Các dấu hiệu chính</h3>
                </div>
                <ol className="mt-3 space-y-2 text-sm leading-6">
                  {reasons.map((reason, index) => (
                    <li key={`${reason.text}:${index}`} className="flex gap-2">
                      <span className="mt-0.5 font-bold text-primary">{index + 1}.</span>
                      <span>{reason.text}</span>
                    </li>
                  ))}
                </ol>
              </section>
            )}
            {mode === "simple" && uncertainties.length > 0 && (
              <section aria-labelledby="agent-uncertainties-heading" className="rounded-2xl border border-amber-500/25 bg-amber-500/8 p-4">
                <h3 id="agent-uncertainties-heading" className="flex items-center gap-2 text-sm font-semibold"><CircleHelp className="size-4" />Điều chưa xác minh được</h3>
                <ul className="mt-2 space-y-1 text-xs leading-5 text-muted-foreground">
                  {uncertainties.map((item) => <li key={item}>• {item}</li>)}
                </ul>
              </section>
            )}
            {mode === "simple" ? (
              <>
                <details className="group rounded-2xl border border-border bg-background/45">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold">
                    Đã kiểm tra những gì?
                    <ChevronDown className="size-4 transition-transform group-open:rotate-180" aria-hidden="true" />
                  </summary>
                  <div className="space-y-5 border-t border-border/70 p-4">
                    <InvestigationTimelineV4 lifecycle={completed.lifecycle} steps={completed.steps} errors={completed.errors} mode="simple" />
                    <EvidenceDeck evidence={completed.evidence} mode="simple" />
                    <AnalysisLimitations limitations={latest!.limitations} />
                  </div>
                </details>
                <details className="group rounded-2xl border border-border bg-background/45">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold">
                    Báo cáo hoặc yêu cầu xem xét
                    <ChevronDown className="size-4 transition-transform group-open:rotate-180" aria-hidden="true" />
                  </summary>
                  <div className="space-y-4 border-t border-border/70 p-4">
                    <AnalysisReportForm analysisId={latest!.analysis_id} securityApi={api} />
                    <AnalysisAppealForm analysisId={latest!.analysis_id} securityApi={api} />
                  </div>
                </details>
              </>
            ) : (
              <>
                <AnalysisReportForm analysisId={latest!.analysis_id} securityApi={api} />
                <AnalysisAppealForm analysisId={latest!.analysis_id} securityApi={api} />
              </>
            )}
          </>
        ) : (
          <div className="rounded-xl border border-dashed border-border p-5 text-center">
            <ShieldCheck className="mx-auto size-5 text-muted-foreground" />
            <p className="mt-2 text-sm font-semibold">{busy ? "Đang chờ verdict" : "Chưa có hành động được khuyến nghị"}</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Frontend không tự tính verdict, score hoặc hành động khi API chưa trả kết luận.
            </p>
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
  latest: SecurityScopeResponseV4 | null;
  busy: boolean;
  api: SecurityAnalysisApi;
  onSubmit(message: string): void;
  onRetry(): void;
  onReset(): void;
}) {
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>("conversation");
  const [mode, setMode] = useState<SecurityPresentationMode>("simple");
  const analysisLabel = latest?.analysis_id ? latest.analysis_id.slice(0, 8) : "pending";
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
          <p className="micro-label text-primary">ACTIVE CASE / {analysisLabel}</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-[-0.025em] sm:text-3xl">
            {mode === "simple" ? "Trợ lý an toàn số" : "Security investigation workspace"}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {latest ? `${latest.status} · ${latest.scope_decision}` : "Đang tạo case từ nội dung intake"}
          </p>
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

      <div className={cn("grid rounded-xl border border-border bg-card p-1 lg:hidden", mode === "simple" ? "grid-cols-2" : "grid-cols-3")} role="tablist" aria-label="Khu vực case">
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
