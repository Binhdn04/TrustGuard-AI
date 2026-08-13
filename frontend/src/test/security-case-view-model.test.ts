import { describe, expect, it } from "vitest";

import { mapSecurityCaseViewModel } from "@/lib/mappers/security-case-view-model";
import { completedSecurityCase, securityLifecycleEvents } from "@/test/fixtures/security-case-v4";

describe("security case view model", () => {
  it("maps only source-backed nodes and relationships", () => {
    const viewModel = mapSecurityCaseViewModel(completedSecurityCase());

    expect(viewModel.signalNodes.some((node) => node.id === "step-not-returned")).toBe(false);
    expect(viewModel.signalNodes.some((node) => node.id === "evidence:not-returned")).toBe(false);
    expect(viewModel.signalEdges).toContainEqual(expect.objectContaining({
      from: "step-aaaaaaaaaaaa",
      to: "step-bbbbbbbbbbbb",
      relation: "depends_on",
      sourceRef: "step-bbbbbbbbbbbb.depends_on",
    }));
    expect(viewModel.signalEdges.some((edge) => edge.from === "step-not-returned")).toBe(false);
    expect(viewModel.signalEdges.some((edge) => edge.to === "evidence:not-returned")).toBe(false);
    expect(viewModel.signalEdges.some((edge) => (
      edge.relation === "depends_on" && edge.from.startsWith("evidence:")
    ))).toBe(false);
  });

  it("marks exact decision evidence while preserving every evidence card", () => {
    const viewModel = mapSecurityCaseViewModel(completedSecurityCase());

    expect(viewModel.evidence).toHaveLength(2);
    expect(viewModel.evidence[0]).toEqual(expect.objectContaining({ usedInDecision: true }));
    expect(viewModel.evidence[1]).toEqual(expect.objectContaining({ usedInDecision: false }));
    expect(viewModel.signalEdges.filter((edge) => edge.relation === "used_in_decision")).toEqual([
      expect.objectContaining({ from: "evidence:aaaaaaaaaaaaaaaa", to: "decision" }),
    ]);
  });

  it("keeps backend action order and uses actual lifecycle event timestamps", () => {
    const viewModel = mapSecurityCaseViewModel(completedSecurityCase(), securityLifecycleEvents());

    expect(viewModel.actions.map((action) => action.code)).toEqual([
      "DO_NOT_OPEN_LINK",
      "VERIFY_VIA_OFFICIAL_CHANNEL",
    ]);
    expect(viewModel.lifecycle.map((entry) => [entry.label, entry.sequence, entry.occurredAt])).toEqual([
      ["investigation", 1, "2026-08-13T08:00:01Z"],
      ["completed", 2, "2026-08-13T08:00:03Z"],
    ]);
    expect(viewModel.steps[1].status).toBe("failed");
  });

  it("falls back only to real analysis timestamps when no events were received", () => {
    const viewModel = mapSecurityCaseViewModel(completedSecurityCase());

    expect(viewModel.lifecycle).toEqual([
      expect.objectContaining({ label: "analysis_created", occurredAt: "2026-08-13T08:00:00Z", source: "analysis" }),
      expect.objectContaining({ label: "analysis_completed", occurredAt: "2026-08-13T08:00:03Z", source: "analysis" }),
    ]);
  });
});
