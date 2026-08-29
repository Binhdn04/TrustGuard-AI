import { afterEach, describe, expect, it, vi } from "vitest";

import {
  subscribeToAnalysisProgress,
  type ProgressTransportApi,
} from "../src/analysis/event-stream";
import type { ActiveAnalysisPublic, AnalysisEventPublic } from "../src/contracts/internal";

const analysisId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";
const eventId = "0e8bfbc6-ec37-4919-aea7-11fd6e90d334";
const createdAt = "2026-08-29T10:00:00.000Z";
const active: ActiveAnalysisPublic = {
  analysisId,
  executionMode: "async",
  status: "queued",
  cursor: null,
  lastSequence: 0,
  createdAt,
  observedAt: createdAt,
};

function progressEvent(sequence: number): AnalysisEventPublic {
  return {
    eventId,
    analysisId,
    sequence,
    status: "running",
    step: "understanding",
    kind: "progress",
    progressState: "started",
    occurredAt: createdAt,
  };
}

class FakeWebSocket {
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  readonly close = vi.fn(() => this.onclose?.({} as CloseEvent));

  open(): void {
    this.onopen?.({} as Event);
  }

  message(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) } as MessageEvent);
  }

  disconnect(): void {
    this.onclose?.({} as CloseEvent);
  }
}

function wireEvent(sequence: number, status = "running", kind = "progress") {
  return {
    event_id: sequence === 1 ? eventId : crypto.randomUUID(),
    analysis_id: analysisId,
    sequence,
    status,
    step: "understanding",
    kind,
    progress_state: kind === "progress" ? "started" : null,
    occurred_at: createdAt,
  };
}

describe("Phase 6 event transport", () => {
  afterEach(() => vi.useRealTimers());

  it("resumes from polling state, connects with the advanced cursor and commits WebSocket progress", async () => {
    const socket = new FakeWebSocket();
    const issueTicket = vi.fn().mockResolvedValue({ url: "ws://localhost:8000/stream?ticket=one" });
    const commitObservation = vi.fn().mockResolvedValue(undefined);
    const api: ProgressTransportApi = {
      getEvents: vi.fn().mockResolvedValue({ events: [progressEvent(1)], nextCursor: "MQ" }),
      getSnapshot: vi.fn().mockResolvedValue({ analysisId, status: "running", terminal: false, createdAt }),
      issueTicket,
      commitObservation,
    };
    const onProgress = vi.fn();
    const onTransportChange = vi.fn();
    const subscription = subscribeToAnalysisProgress(api, active, {
      onProgress,
      onStatus: vi.fn(),
      onTransportChange,
      onTerminal: vi.fn(),
    }, { webSocketFactory: () => socket as unknown as WebSocket });

    await vi.waitFor(() => expect(issueTicket).toHaveBeenCalledWith(analysisId, "MQ"));
    socket.open();
    socket.message(wireEvent(2));
    await vi.waitFor(() => expect(commitObservation).toHaveBeenLastCalledWith(
      analysisId,
      { cursor: "Mg", lastSequence: 2, status: "running" },
    ));

    expect(onProgress).toHaveBeenLastCalledWith(expect.objectContaining({ sequence: 2 }));
    expect(onTransportChange).toHaveBeenCalledWith("connected");
    subscription.stop();
  });

  it("uses fresh tickets for bounded reconnects then falls back to cursor polling", async () => {
    vi.useFakeTimers();
    const issueTicket = vi.fn().mockRejectedValue(new Error("ticket unavailable"));
    const getEvents = vi.fn()
      .mockResolvedValueOnce({ events: [], nextCursor: null })
      .mockResolvedValue({ events: [], nextCursor: null });
    const api: ProgressTransportApi = {
      issueTicket,
      getEvents,
      getSnapshot: vi.fn().mockResolvedValue({ analysisId, status: "running", terminal: false, createdAt }),
      commitObservation: vi.fn(),
    };
    const onTransportChange = vi.fn();
    const subscription = subscribeToAnalysisProgress(api, active, {
      onProgress: vi.fn(),
      onStatus: vi.fn(),
      onTransportChange,
      onTerminal: vi.fn(),
    }, { maxReconnectAttempts: 2, pollIntervalMs: 100 });

    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(500);
    await vi.advanceTimersByTimeAsync(1_000);

    expect(issueTicket).toHaveBeenCalledTimes(3);
    expect(onTransportChange).toHaveBeenCalledWith("polling_fallback");
    expect(getEvents).toHaveBeenCalledTimes(2);
    subscription.stop();
  });

  it("ignores malformed notifications and fetches the authoritative final snapshot", async () => {
    const socket = new FakeWebSocket();
    const terminal = { analysisId, status: "completed" as const, terminal: true, createdAt };
    const getSnapshot = vi.fn()
      .mockResolvedValueOnce({ analysisId, status: "running", terminal: false, createdAt })
      .mockResolvedValueOnce(terminal);
    const issueTicket = vi.fn().mockResolvedValue({ url: "ws://localhost:8000/stream?ticket=one" });
    const api: ProgressTransportApi = {
      getEvents: vi.fn().mockResolvedValue({ events: [], nextCursor: null }),
      getSnapshot,
      issueTicket,
      commitObservation: vi.fn().mockResolvedValue(undefined),
    };
    const onTerminal = vi.fn();
    subscribeToAnalysisProgress(api, active, {
      onProgress: vi.fn(),
      onStatus: vi.fn(),
      onTransportChange: vi.fn(),
      onTerminal,
    }, { webSocketFactory: () => socket as unknown as WebSocket });

    await vi.waitFor(() => expect(issueTicket).toHaveBeenCalledTimes(1));
    socket.message({ message: "malformed" });
    socket.message(wireEvent(1, "completed", "final"));

    await vi.waitFor(() => expect(onTerminal).toHaveBeenCalledWith(terminal));
    expect(getSnapshot).toHaveBeenCalledTimes(2);
  });
});
