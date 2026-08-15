import { useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ActionRiskPanel } from "@/components/analysis/action-risk-panel";
import { CaseSignalMap } from "@/components/analysis/case-signal-map";
import { EvidenceDeck } from "@/components/analysis/evidence-deck";
import { InvestigationTimelineV4 } from "@/components/analysis/investigation-timeline-v4";
import { SimpleAnalystToggle } from "@/components/analysis/simple-analyst-toggle";
import {
  mapSecurityCaseViewModel,
  type SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import { completedSecurityCase, securityLifecycleEvents } from "@/test/fixtures/security-case-v4";

function Presentation() {
  const [mode, setMode] = useState<SecurityPresentationMode>("simple");
  const viewModel = mapSecurityCaseViewModel(completedSecurityCase(), securityLifecycleEvents());
  return (
    <>
      <SimpleAnalystToggle mode={mode} onChange={setMode} />
      <ActionRiskPanel viewModel={viewModel} mode={mode} />
      <CaseSignalMap nodes={viewModel.signalNodes} edges={viewModel.signalEdges} mode={mode} />
      <InvestigationTimelineV4 lifecycle={viewModel.lifecycle} steps={viewModel.steps} errors={viewModel.errors} mode={mode} />
      <EvidenceDeck evidence={viewModel.evidence} mode={mode} />
    </>
  );
}

describe("FE4 security case presentation", () => {
  it.each([
    ["SAFE", "Chưa phát hiện rủi ro"],
    ["INSUFFICIENT_EVIDENCE", "Chưa đủ bằng chứng"],
  ] as const)("renders the backend %s verdict without promoting it to a warning", (risk, label) => {
    const result = completedSecurityCase({
      risk,
      score: risk === "SAFE" ? 5 : null,
      confidence: risk === "SAFE" ? 0.91 : null,
      recommended_actions: [],
      explanation: risk === "SAFE" ? "No supported security risk was observed." : "Available evidence is inconclusive.",
    });
    render(<ActionRiskPanel viewModel={mapSecurityCaseViewModel(result)} mode="simple" />);

    expect(screen.getByRole("heading", { name: label })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /Rủi ro cao|Nguy hiểm/ })).not.toBeInTheDocument();
  });

  it("places the primary backend recommendation before risk metrics", () => {
    render(<Presentation />);

    fireEvent.click(screen.getByRole("button", { name: "analyst" }));

    const recommendation = screen.getByText("Không mở liên kết");
    const score = screen.getByText("91/100");
    expect(recommendation.compareDocumentPosition(score) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Rủi ro cao" })).toBeInTheDocument();
    expect(screen.getByText("Tự liên hệ qua kênh chính thức")).toBeInTheDocument();
  });

  it("keeps all evidence and marks only exact explanation references", () => {
    render(<Presentation />);

    const deck = screen.getByRole("heading", { name: "Recorded observations" }).closest("section");
    expect(deck).not.toBeNull();
    const evidenceDeck = within(deck as HTMLElement);
    expect(evidenceDeck.getByText("URL asks for account credentials.")).toBeInTheDocument();
    expect(evidenceDeck.getByText("Claimed brand does not match the observed domain.")).toBeInTheDocument();
    expect(evidenceDeck.getAllByText("Used in decision")).toHaveLength(1);
    expect(screen.getByRole("list", { name: "Signal relationships" })).toHaveTextContent("depends_on");
  });

  it("changes presentation depth without changing the verdict or evidence set", () => {
    render(<Presentation />);

    expect(screen.queryByText("ruleset:security-url-v1")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "analyst" }));

    expect(screen.getByRole("button", { name: "analyst" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("heading", { name: "Rủi ro cao" })).toBeInTheDocument();
    expect(screen.getByText("ruleset:security-url-v1")).toBeInTheDocument();
    expect(screen.getAllByText("evidence:aaaaaaaaaaaaaaaa").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Depends on:/).some((item) => item.textContent?.includes("step-aaaaaaaaaaaa"))).toBe(true);
    expect(screen.queryByText(/screenshot|PCAP|ASN|geolocation/i)).not.toBeInTheDocument();
  });
});
