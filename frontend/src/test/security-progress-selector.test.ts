import { describe, expect, it } from "vitest";

import { selectSecurityProgress } from "@/lib/security-progress";

const analysisId = "10000000-0000-4000-8000-000000000001";

describe("security progress selector", () => {
  it("returns no progress without an active analysis or matching events", () => {
    expect(selectSecurityProgress(null, [])).toEqual({ latest: null, timeline: [] });
    expect(selectSecurityProgress(analysisId, [{
      event_id: "other", analysis_id: "other-analysis", sequence: 1, kind: "progress",
    }])).toEqual({ latest: null, timeline: [] });
  });

  it("deduplicates replay and never regresses to a delayed lower sequence", () => {
    const progress = selectSecurityProgress(analysisId, [
      {
        event_id: "investigation-started", analysis_id: analysisId, sequence: 3, kind: "progress",
        step: "investigation", progress_state: "started",
      },
      {
        event_id: "understanding-started", analysis_id: analysisId, sequence: 2, kind: "progress",
        step: "understanding", progress_state: "started",
      },
      {
        event_id: "investigation-completed", analysis_id: analysisId, sequence: 4, kind: "progress",
        step: "investigation", progress_state: "completed",
      },
      {
        event_id: "investigation-started", analysis_id: analysisId, sequence: 3, kind: "progress",
        step: "investigation", progress_state: "started",
      },
    ]);

    expect(progress.latest).toEqual(expect.objectContaining({
      eventId: "investigation-completed",
      sequence: 4,
      stage: "investigation",
      state: "completed",
    }));
    expect(progress.timeline.map((entry) => entry.eventId)).toEqual([
      "understanding-started",
      "investigation-started",
      "investigation-completed",
    ]);
  });

  it("uses a generic label for unknown or malformed event fields without reading sensitive payload fields", () => {
    const progress = selectSecurityProgress(analysisId, [
      null,
      { event_id: "bad-sequence", analysis_id: analysisId, sequence: 0, kind: "progress" },
      {
        event_id: "unknown-progress", analysis_id: analysisId, sequence: 5, kind: "progress",
        step: "url_reputation", progress_state: "started",
        message: "raw provider output must not appear",
        risk_hint: "MALICIOUS",
        evidence_refs: ["secret-evidence-ref"],
      },
    ]);

    expect(progress.latest).toEqual(expect.objectContaining({
      sequence: 5,
      stage: null,
      state: "started",
      label: "Đang tiếp tục kiểm tra nội dung",
    }));
    expect(progress.timeline).toEqual([]);
  });
});
