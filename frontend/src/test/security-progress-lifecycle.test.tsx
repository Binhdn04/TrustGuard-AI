import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { subscribeToSecurityEvents } from "@/lib/api/security-event-stream";
import { useSecurityCase } from "@/lib/hooks/use-security-case";
import { completedSecurityCase } from "@/test/fixtures/security-case-v4";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityAnalysisEventV4 } from "@/types/generated/api-v4";

vi.mock("@/lib/api/security-event-stream", () => ({
  subscribeToSecurityEvents: vi.fn(),
}));

const firstAnalysisId = "10000000-0000-4000-8000-000000000001";
const secondAnalysisId = "20000000-0000-4000-8000-000000000002";

function accepted(analysisId: string) {
  return {
    contract_version: "v4" as const,
    analysis_id: analysisId,
    conversation_id: "30000000-0000-4000-8000-000000000003",
    conversation_version: 1,
    status: "queued" as const,
    created_at: "2026-08-13T08:00:00Z",
  };
}

function progress(
  analysisId: string,
  sequence: number,
  step: "understanding" | "investigation",
): SecurityAnalysisEventV4 {
  return {
    event_id: `${analysisId}-${sequence}`,
    analysis_id: analysisId,
    sequence,
    status: "running",
    step,
    step_id: step,
    kind: "progress",
    progress_state: "started",
    message: `progress.${step}.started`,
    evidence_refs: [],
    risk_hint: null,
    occurred_at: "2026-08-13T08:00:00Z",
  };
}

function terminal(analysisId: string): SecurityAnalysisEventV4 {
  return {
    event_id: `${analysisId}-final`,
    analysis_id: analysisId,
    sequence: 9,
    status: "completed",
    step: "completed",
    step_id: null,
    kind: "final",
    progress_state: null,
    message: null,
    evidence_refs: [],
    risk_hint: null,
    occurred_at: "2026-08-13T08:00:01Z",
  };
}

function testApi() {
  return {
    getCapabilities: vi.fn().mockResolvedValue({ security_async_execution: true }),
    createAnalysis: vi.fn()
      .mockResolvedValueOnce(accepted(firstAnalysisId))
      .mockResolvedValueOnce(accepted(secondAnalysisId)),
    getAnalysis: vi.fn().mockResolvedValue(completedSecurityCase({ analysis_id: firstAnalysisId })),
  } as unknown as SecurityAnalysisApi;
}

function streamCallbacks(call: number) {
  const callbacks = vi.mocked(subscribeToSecurityEvents).mock.calls[call]?.[2];
  if (!callbacks) throw new Error("stream subscription was not created");
  return callbacks;
}

describe("security progress lifecycle", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("keeps the latest sequence across websocket/polling replay and removes prior progress on reset", async () => {
    const stop = vi.fn();
    vi.mocked(subscribeToSecurityEvents).mockReturnValue({ stop });
    const api = testApi();
    const { result } = renderHook(() => useSecurityCase(api));

    act(() => result.current.submit("Kiểm tra yêu cầu gửi OTP"));
    await waitFor(() => expect(subscribeToSecurityEvents).toHaveBeenCalledTimes(1));
    const firstStream = streamCallbacks(0);

    act(() => {
      firstStream.onTransportChange("connected");
      firstStream.onEvents([progress(firstAnalysisId, 3, "investigation")]);
      firstStream.onTransportChange("polling_fallback");
      firstStream.onEvents([progress(firstAnalysisId, 2, "understanding")]);
      firstStream.onTransportChange("reconnecting");
    });

    expect(result.current.transport).toBe("reconnecting");
    expect(result.current.progress.latest).toEqual(expect.objectContaining({
      analysisId: firstAnalysisId,
      sequence: 3,
      stage: "investigation",
    }));
    expect(result.current.lifecycleEvents.map((event) => event.sequence)).toEqual([2, 3]);
    expect(result.current.turns).toEqual([expect.objectContaining({
      message: "Kiểm tra yêu cầu gửi OTP",
      analysisId: firstAnalysisId,
      result: null,
    })]);

    act(() => result.current.reset());
    expect(stop).toHaveBeenCalledTimes(1);
    expect(result.current.progress).toEqual({ latest: null, timeline: [] });
    expect(result.current.lifecycleEvents).toEqual([]);

    act(() => result.current.submit("Kiểm tra trường hợp mới"));
    await waitFor(() => expect(subscribeToSecurityEvents).toHaveBeenCalledTimes(2));
    const secondStream = streamCallbacks(1);
    act(() => {
      firstStream.onEvents([progress(firstAnalysisId, 4, "investigation")]);
      secondStream.onEvents([progress(secondAnalysisId, 1, "understanding")]);
    });

    expect(result.current.progress.latest).toEqual(expect.objectContaining({
      analysisId: secondAnalysisId,
      sequence: 1,
      stage: "understanding",
    }));
  });

  it("fetches the terminal result after an unpresentable event and replaces progress without changing submit calls", async () => {
    const stop = vi.fn();
    vi.mocked(subscribeToSecurityEvents).mockReturnValue({ stop });
    const api = testApi();
    const { result } = renderHook(() => useSecurityCase(api));

    act(() => result.current.submit("Kiểm tra yêu cầu gửi OTP"));
    await waitFor(() => expect(subscribeToSecurityEvents).toHaveBeenCalledTimes(1));
    const callbacks = streamCallbacks(0);
    const unpresentableProgress = {
      ...progress(firstAnalysisId, 4, "investigation"),
      step: "provider_dns_detail",
      message: "private provider detail must not be presented",
    };

    act(() => callbacks.onEvents([unpresentableProgress, terminal(firstAnalysisId)]));
    await waitFor(() => expect(api.getAnalysis).toHaveBeenCalledWith(firstAnalysisId));
    await waitFor(() => expect(result.current.state).toBe("COMPLETED"));

    expect(result.current.progress).toEqual({ latest: null, timeline: [] });
    expect(result.current.turns).toEqual([expect.objectContaining({
      analysisId: undefined,
      result: completedSecurityCase({ analysis_id: firstAnalysisId }),
    })]);
    expect(api.createAnalysis).toHaveBeenCalledWith(expect.objectContaining({
      message: "Kiểm tra yêu cầu gửi OTP",
      execution_mode: "async",
    }), { idempotencyKey: expect.any(String) });
    expect(stop).toHaveBeenCalledTimes(1);
  });
});
