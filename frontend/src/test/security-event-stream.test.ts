import { afterEach, describe, expect, it, vi } from "vitest";

import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityAnalysisEventV4 } from "@/types/generated/api-v4";

describe("security event stream", () => {
  afterEach(() => vi.useRealTimers());

  it("falls back to cursor polling and deduplicates replay after ticket failure", async () => {
    vi.useFakeTimers();
    const event: SecurityAnalysisEventV4 = {
      event_id: "event-1", analysis_id: "analysis-1", sequence: 1, status: "running",
      step: "investigation", kind: "progress", step_id: "investigation", message: null,
      evidence_refs: [], risk_hint: null, occurred_at: "2026-08-13T08:00:00Z",
    };
    const getAnalysisEvents = vi.fn()
      .mockResolvedValueOnce({ contract_version: "v4", events: [event], next_cursor: "MQ" })
      .mockResolvedValue({ contract_version: "v4", events: [event], next_cursor: "MQ" });
    const api = {
      createWebSocketTicket: vi.fn().mockRejectedValue(new Error("stream unavailable")),
      getAnalysisEvents,
    } as unknown as SecurityAnalysisApi;
    const onEvents = vi.fn();
    const onTransportChange = vi.fn();
    const subscription = subscribeToSecurityEvents(api, "analysis-1", { onEvents, onTransportChange }, { pollIntervalMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(100);

    expect(onTransportChange).toHaveBeenCalledWith("polling_fallback");
    expect(getAnalysisEvents).toHaveBeenLastCalledWith("analysis-1", { cursor: "MQ", limit: 100 });
    expect(onEvents).toHaveBeenCalledTimes(1);
    subscription.stop();
  });
});
