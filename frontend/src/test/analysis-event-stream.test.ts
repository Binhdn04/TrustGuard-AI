import { afterEach, describe, expect, it, vi } from "vitest";

import { subscribeToAnalysisEvents } from "@/lib/api/analysis-event-stream";
import type { AnalysisApi } from "@/lib/api/analysis-api.types";
import type { AnalysisEventV3 } from "@/types/generated/api-v3";

describe("analysis event stream", () => {
  afterEach(() => vi.useRealTimers());

  it("falls back to polling, advances the cursor and deduplicates replayed events", async () => {
    vi.useFakeTimers();
    const event: AnalysisEventV3 = {
      event_id: "event-1",
      analysis_id: "analysis-1",
      sequence: 1,
      event_type: "analysis_status",
      occurred_at: "2026-08-08T08:00:00Z",
      payload: { status: "running" },
    };
    const createWebSocketTicket = vi.fn().mockRejectedValue(new Error("not implemented"));
    const getAnalysisEvents = vi.fn()
      .mockResolvedValueOnce({ contract_version: "v3", events: [event], next_cursor: "cursor-1" })
      .mockResolvedValue({ contract_version: "v3", events: [event], next_cursor: "cursor-1" });
    const onEvents = vi.fn();
    const onTransportChange = vi.fn();

    const subscription = subscribeToAnalysisEvents(
      { createWebSocketTicket, getAnalysisEvents } as unknown as AnalysisApi,
      "analysis-1",
      { onEvents, onTransportChange },
      { pollIntervalMs: 100 },
    );
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(100);

    expect(onTransportChange).toHaveBeenCalledWith("polling_fallback");
    expect(getAnalysisEvents).toHaveBeenLastCalledWith("analysis-1", { cursor: "cursor-1", limit: 100 });
    expect(onEvents).toHaveBeenCalledTimes(1);
    expect(onEvents).toHaveBeenCalledWith([event]);

    subscription.stop();
  });
});
