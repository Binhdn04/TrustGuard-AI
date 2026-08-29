import type { AnalysisSnapshot } from "../api/client";
import type { ActiveAnalysisPublic, AnalysisEventPublic } from "../contracts/internal";
import {
  parseWebSocketEvent,
  reduceAnalysisEvents,
  type ProgressCursorState,
  type ProgressDisplay,
} from "./progress-selector";

export type AnalysisTransportState =
  | "resuming"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "polling_fallback"
  | "disconnected";

export interface ProgressTransportApi {
  issueTicket(analysisId: string, cursor: string | null): Promise<{ url: string }>;
  getEvents(
    analysisId: string,
    cursor: string | null,
  ): Promise<{ events: AnalysisEventPublic[]; nextCursor: string | null }>;
  getSnapshot(analysisId: string): Promise<AnalysisSnapshot>;
  commitObservation(analysisId: string, state: ProgressCursorState): Promise<void>;
}

export interface ProgressCallbacks {
  onProgress(progress: ProgressDisplay): void;
  onStatus(status: ActiveAnalysisPublic["status"]): void;
  onTransportChange(state: AnalysisTransportState): void;
  onTerminal(snapshot: AnalysisSnapshot): void;
  onError?(error: unknown): void;
}

interface ProgressTransportOptions {
  pollIntervalMs?: number;
  maxPollIntervalMs?: number;
  maxReconnectAttempts?: number;
  webSocketFactory?: (url: string) => WebSocket;
}

export function subscribeToAnalysisProgress(
  api: ProgressTransportApi,
  initial: ActiveAnalysisPublic,
  callbacks: ProgressCallbacks,
  options: ProgressTransportOptions = {},
): { stop(): void } {
  const basePollInterval = options.pollIntervalMs ?? 1_500;
  const maxPollInterval = options.maxPollIntervalMs ?? 5_000;
  const maxReconnectAttempts = options.maxReconnectAttempts ?? 3;
  const socketFactory = options.webSocketFactory ?? ((url: string) => new WebSocket(url));
  const seenEventIds = new Set<string>();
  let state: ProgressCursorState = {
    cursor: initial.cursor,
    lastSequence: initial.lastSequence,
    status: initial.status,
  };
  let stopped = false;
  let reconnectAttempts = 0;
  let pollDelay = basePollInterval;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let socket: WebSocket | null = null;
  let processing = Promise.resolve();
  let finalizing = false;

  const schedule = (task: () => void, delay: number): void => {
    if (!stopped) timer = setTimeout(task, delay);
  };

  const stopInternal = (): void => {
    stopped = true;
    if (timer !== null) clearTimeout(timer);
    socket?.close();
    callbacks.onTransportChange("disconnected");
  };

  const checkSnapshot = async (): Promise<boolean> => {
    if (stopped || finalizing) return stopped;
    finalizing = true;
    try {
      const snapshot = await api.getSnapshot(initial.analysisId);
      if (stopped) return true;
      state = { ...state, status: snapshot.status };
      callbacks.onStatus(snapshot.status);
      if (snapshot.terminal || snapshot.status === "completed" || snapshot.status === "failed") {
        callbacks.onTerminal(snapshot);
        stopInternal();
        return true;
      }
      return false;
    } finally {
      finalizing = false;
    }
  };

  const applyEvents = async (events: AnalysisEventPublic[], nextCursor: string | null): Promise<boolean> => {
    if (stopped) return true;
    const reduced = reduceAnalysisEvents(initial.analysisId, state, events, seenEventIds, nextCursor);
    const changed = reduced.advanced || reduced.cursor !== state.cursor || reduced.status !== state.status;
    state = {
      cursor: reduced.cursor,
      lastSequence: reduced.lastSequence,
      status: reduced.status,
    };
    if (reduced.latest !== null) callbacks.onProgress(reduced.latest);
    callbacks.onStatus(reduced.status);
    if (changed) await api.commitObservation(initial.analysisId, state);
    if (reduced.terminal) return checkSnapshot();
    return false;
  };

  const poll = async (): Promise<void> => {
    if (stopped) return;
    callbacks.onTransportChange("polling_fallback");
    try {
      const page = await api.getEvents(initial.analysisId, state.cursor);
      if (await applyEvents(page.events, page.nextCursor)) return;
      if (await checkSnapshot()) return;
      pollDelay = basePollInterval;
    } catch (error: unknown) {
      callbacks.onError?.(error);
      pollDelay = Math.min(Math.max(basePollInterval, pollDelay * 2), maxPollInterval);
    }
    schedule(() => void poll(), pollDelay);
  };

  const fallbackToPolling = (): void => {
    socket?.close();
    socket = null;
    void poll();
  };

  const connect = async (): Promise<void> => {
    if (stopped) return;
    callbacks.onTransportChange(reconnectAttempts === 0 ? "connecting" : "reconnecting");
    try {
      const issued = await api.issueTicket(initial.analysisId, state.cursor);
      if (stopped) return;
      const current = socketFactory(issued.url);
      socket = current;
      current.onopen = () => callbacks.onTransportChange("connected");
      current.onmessage = (message) => {
        if (typeof message.data !== "string") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(message.data);
        } catch {
          return;
        }
        const event = parseWebSocketEvent(parsed);
        if (event === null) return;
        processing = processing.then(async () => {
          const terminal = await applyEvents([event], null);
          if (!terminal) reconnectAttempts = 0;
        }).catch((error: unknown) => callbacks.onError?.(error));
      };
      current.onerror = () => current.close();
      current.onclose = () => {
        if (stopped) return;
        void processing.finally(() => {
          if (stopped) return;
          reconnectAttempts += 1;
          if (reconnectAttempts > maxReconnectAttempts) fallbackToPolling();
          else schedule(() => void connect(), Math.min(500 * 2 ** (reconnectAttempts - 1), 4_000));
        });
      };
    } catch (error: unknown) {
      callbacks.onError?.(error);
      reconnectAttempts += 1;
      if (reconnectAttempts > maxReconnectAttempts) fallbackToPolling();
      else schedule(() => void connect(), Math.min(500 * 2 ** (reconnectAttempts - 1), 4_000));
    }
  };

  const resume = async (): Promise<void> => {
    callbacks.onTransportChange("resuming");
    try {
      const page = await api.getEvents(initial.analysisId, state.cursor);
      if (await applyEvents(page.events, page.nextCursor)) return;
      if (await checkSnapshot()) return;
    } catch (error: unknown) {
      callbacks.onError?.(error);
    }
    await connect();
  };

  void resume();
  return { stop: stopInternal };
}
