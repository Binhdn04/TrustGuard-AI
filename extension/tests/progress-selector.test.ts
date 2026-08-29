import { describe, expect, it } from "vitest";

import {
  cursorForSequence,
  parseWebSocketEvent,
  reduceAnalysisEvents,
} from "../src/analysis/progress-selector";
import type { AnalysisEventPublic } from "../src/contracts/internal";

const analysisId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";
const otherAnalysisId = "0e8bfbc6-ec37-4919-aea7-11fd6e90d334";
const occurredAt = "2026-08-29T10:00:00.000Z";

function event(
  sequence: number,
  overrides: Partial<AnalysisEventPublic> = {},
): AnalysisEventPublic {
  return {
    eventId: crypto.randomUUID(),
    analysisId,
    sequence,
    status: "running",
    step: "understanding",
    kind: "progress",
    progressState: "started",
    occurredAt,
    ...overrides,
  };
}

describe("Phase 6 progress selector", () => {
  it("parses WebSocket wire events while stripping arbitrary backend fields", () => {
    expect(parseWebSocketEvent({
      event_id: otherAnalysisId,
      analysis_id: analysisId,
      sequence: 1,
      status: "running",
      step: "understanding",
      kind: "progress",
      progress_state: "started",
      occurred_at: occurredAt,
      message: "raw provider detail",
      evidence_refs: ["private-ref"],
      risk_hint: "HIGH_RISK",
    })).toEqual({
      eventId: otherAnalysisId,
      analysisId,
      sequence: 1,
      status: "running",
      step: "understanding",
      kind: "progress",
      progressState: "started",
      occurredAt,
    });
    expect(parseWebSocketEvent({ analysis_id: analysisId, sequence: 1 })).toBeNull();
  });

  it("sorts, deduplicates, rejects wrong-analysis events and never regresses sequence", () => {
    const duplicateId = crypto.randomUUID();
    const seen = new Set<string>();
    const reduced = reduceAnalysisEvents(
      analysisId,
      { cursor: "MQ", lastSequence: 1, status: "running" },
      [
        event(3, { eventId: duplicateId, step: "investigation", progressState: "completed" }),
        event(2, { step: "understanding", progressState: "completed" }),
        event(3, { eventId: duplicateId, step: "investigation" }),
        event(4, { analysisId: otherAnalysisId }),
        event(1),
      ],
      seen,
    );

    expect(reduced).toMatchObject({
      cursor: "Mw",
      lastSequence: 3,
      status: "running",
      terminal: false,
      advanced: true,
      latest: {
        sequence: 3,
        stage: "investigation",
        state: "completed",
        label: "Đã hoàn tất kiểm tra các tín hiệu liên quan",
      },
    });
    expect(seen.has(duplicateId)).toBe(true);
  });

  it("uses generic copy for unknown stages and treats final only as a final-fetch trigger", () => {
    const reduced = reduceAnalysisEvents(
      analysisId,
      { cursor: null, lastSequence: 0, status: "queued" },
      [
        event(1, { step: "provider_private_step" }),
        event(2, { kind: "final", status: "completed", progressState: null }),
      ],
      new Set(),
      "Mg",
    );
    expect(reduced).toMatchObject({
      cursor: "Mg",
      lastSequence: 2,
      status: "completed",
      terminal: true,
      latest: { label: "Đang tiếp tục kiểm tra nội dung", stage: null },
    });
    expect(cursorForSequence(4)).toBe("NA");
  });
});
