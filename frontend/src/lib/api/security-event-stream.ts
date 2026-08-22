import type { AnalysisTransportState } from "@/types/analysis-view-model";
import type { SecurityAnalysisEventV4 } from "@/types/generated/api-v4";

import type { SecurityAnalysisApi } from "./security-analysis-api.types";
import { resolveSecurityApiUrl } from "./security-api-url";

interface Callbacks {
  onEvents(events: SecurityAnalysisEventV4[]): void;
  onTransportChange(state: AnalysisTransportState): void;
  onError?(error: unknown): void;
}

interface Options {
  pollIntervalMs?: number;
  maxReconnectAttempts?: number;
  webSocketFactory?: (url: string) => WebSocket;
}

function streamUrl(path: string, apiUrl: string, ticket: string, cursor: string | null): string {
  const url = new URL(path, apiUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("ticket", ticket);
  if (cursor) url.searchParams.set("cursor", cursor);
  return url.toString();
}

export function subscribeToSecurityEvents(
  api: SecurityAnalysisApi,
  analysisId: string,
  callbacks: Callbacks,
  options: Options = {},
): { stop(): void } {
  const seen = new Set<string>();
  const pollInterval = options.pollIntervalMs ?? 1_500;
  const maxReconnects = options.maxReconnectAttempts ?? 3;
  const socketFactory = options.webSocketFactory ?? ((url: string) => new WebSocket(url));
  let cursor: string | null = null;
  let stopped = false;
  let reconnects = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let socket: WebSocket | null = null;

  const emit = (events: SecurityAnalysisEventV4[]) => {
    const unique = events
      .filter((event) => event.analysis_id === analysisId && !seen.has(event.event_id))
      .sort((left, right) => left.sequence - right.sequence);
    unique.forEach((event) => seen.add(event.event_id));
    if (unique.length) callbacks.onEvents(unique);
  };
  const schedule = (task: () => void, delay: number) => {
    if (!stopped) timer = setTimeout(task, delay);
  };
  const poll = async (): Promise<void> => {
    if (stopped) return;
    callbacks.onTransportChange("polling_fallback");
    try {
      const page = await api.getAnalysisEvents(analysisId, { cursor, limit: 100 });
      if (stopped) return;
      emit(page.events);
      cursor = page.next_cursor ?? cursor;
    } catch (error) {
      callbacks.onError?.(error);
    }
    schedule(() => void poll(), pollInterval);
  };
  const connect = async (): Promise<void> => {
    callbacks.onTransportChange(reconnects ? "reconnecting" : "connecting");
    let apiUrl: string;
    try {
      apiUrl = resolveSecurityApiUrl();
    } catch (error) {
      callbacks.onError?.(error);
      void poll();
      return;
    }
    try {
      const ticket = await api.createWebSocketTicket(analysisId);
      if (stopped) return;
      const current = socketFactory(streamUrl(ticket.stream_path, apiUrl, ticket.ticket, cursor));
      socket = current;
      current.onopen = () => {
        reconnects = 0;
        callbacks.onTransportChange("connected");
      };
      current.onmessage = (message) => {
        if (typeof message.data !== "string") return;
        try {
          const payload = JSON.parse(message.data) as SecurityAnalysisEventV4;
          emit([payload]);
        } catch {
          // A malformed notification is ignored; cursor polling remains authoritative.
        }
      };
      current.onerror = () => current.close();
      current.onclose = () => {
        if (stopped) return;
        reconnects += 1;
        if (reconnects > maxReconnects) void poll();
        else schedule(() => void connect(), Math.min(500 * 2 ** (reconnects - 1), 4_000));
      };
    } catch (error) {
      callbacks.onError?.(error);
      void poll();
    }
  };
  void connect();
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      socket?.close();
      callbacks.onTransportChange("disconnected");
    },
  };
}
