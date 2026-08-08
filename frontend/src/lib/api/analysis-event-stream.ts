import type { AnalysisEventV3 } from "@/types/generated/api-v3";
import type { AnalysisTransportState } from "@/types/analysis-view-model";

import type { AnalysisApi } from "./analysis-api.types";

export interface AnalysisEventStreamCallbacks {
  onEvents(events: AnalysisEventV3[]): void;
  onTransportChange(state: AnalysisTransportState): void;
  onError?(error: unknown): void;
}

export interface AnalysisEventStreamOptions {
  pollIntervalMs?: number;
  maxReconnectAttempts?: number;
  webSocketFactory?: (url: string) => WebSocket;
}

export interface AnalysisEventSubscription {
  stop(): void;
}

function streamUrl(streamPath: string, ticket: string, cursor: string | null): string {
  const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
  const base = new URL(apiBase);
  const url = new URL(streamPath, base);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (!url.searchParams.has("ticket")) url.searchParams.set("ticket", ticket);
  if (cursor && !url.searchParams.has("cursor")) url.searchParams.set("cursor", cursor);
  return url.toString();
}

interface ParsedSocketMessage {
  events: AnalysisEventV3[];
  nextCursor: string | null;
}

function parseSocketMessage(data: unknown): ParsedSocketMessage {
  if (typeof data !== "string") return { events: [], nextCursor: null };
  try {
    const parsed = JSON.parse(data) as unknown;
    if (Array.isArray(parsed)) return { events: parsed as AnalysisEventV3[], nextCursor: null };
    if (parsed && typeof parsed === "object" && "events" in parsed) {
      const envelope = parsed as { events?: unknown; next_cursor?: unknown; cursor?: unknown };
      return {
        events: Array.isArray(envelope.events) ? (envelope.events as AnalysisEventV3[]) : [],
        nextCursor:
          typeof envelope.next_cursor === "string"
            ? envelope.next_cursor
            : typeof envelope.cursor === "string" ? envelope.cursor : null,
      };
    }
    if (parsed && typeof parsed === "object" && "event_type" in parsed) {
      return { events: [parsed as AnalysisEventV3], nextCursor: null };
    }
  } catch {
    return { events: [], nextCursor: null };
  }
  return { events: [], nextCursor: null };
}

export function subscribeToAnalysisEvents(
  api: AnalysisApi,
  analysisId: string,
  callbacks: AnalysisEventStreamCallbacks,
  options: AnalysisEventStreamOptions = {},
): AnalysisEventSubscription {
  const pollIntervalMs = options.pollIntervalMs ?? 1_500;
  const maxReconnectAttempts = options.maxReconnectAttempts ?? 3;
  const createSocket = options.webSocketFactory ?? ((url: string) => new WebSocket(url));
  const seenEventIds = new Set<string>();
  let cursor: string | null = null;
  let stopped = false;
  let reconnectAttempts = 0;
  let socket: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const schedule = (callback: () => void, delay: number) => {
    if (stopped) return;
    timer = setTimeout(callback, delay);
  };

  const emitUnique = (events: AnalysisEventV3[]) => {
    const unique = events
      .filter((event) => event.analysis_id === analysisId && !seenEventIds.has(event.event_id))
      .sort((left, right) => left.sequence - right.sequence);
    for (const event of unique) seenEventIds.add(event.event_id);
    if (unique.length > 0) callbacks.onEvents(unique);
  };

  const poll = async (): Promise<void> => {
    if (stopped) return;
    callbacks.onTransportChange("polling_fallback");
    try {
      const page = await api.getAnalysisEvents(analysisId, { cursor, limit: 100 });
      if (stopped) return;
      emitUnique(page.events);
      cursor = page.next_cursor ?? cursor;
    } catch (error) {
      if (!stopped) callbacks.onError?.(error);
    }
    schedule(() => void poll(), pollIntervalMs);
  };

  const connect = async (): Promise<void> => {
    if (stopped) return;
    callbacks.onTransportChange(reconnectAttempts === 0 ? "connecting" : "reconnecting");
    try {
      const ticket = await api.createWebSocketTicket(analysisId);
      if (stopped) return;
      const currentSocket = createSocket(streamUrl(ticket.stream_path, ticket.ticket, cursor));
      socket = currentSocket;
      let opened = false;

      currentSocket.onopen = () => {
        opened = true;
        reconnectAttempts = 0;
        callbacks.onTransportChange("connected");
      };
      currentSocket.onmessage = (message) => {
        const parsed = parseSocketMessage(message.data);
        emitUnique(parsed.events);
        cursor = parsed.nextCursor ?? cursor;
      };
      currentSocket.onerror = () => currentSocket.close();
      currentSocket.onclose = () => {
        if (socket === currentSocket) socket = null;
        if (stopped) return;
        reconnectAttempts += 1;
        if (reconnectAttempts > maxReconnectAttempts) {
          void poll();
          return;
        }
        const delay = opened ? 500 : Math.min(500 * 2 ** (reconnectAttempts - 1), 4_000);
        schedule(() => void connect(), delay);
      };
    } catch (error) {
      if (stopped) return;
      callbacks.onError?.(error);
      // Ticket creation can be unavailable during the v2-to-v3 migration.
      // Polling starts immediately so a missing stream never blocks analysis.
      void poll();
    }
  };

  void connect();

  return {
    stop() {
      stopped = true;
      if (timer !== null) clearTimeout(timer);
      socket?.close();
      socket = null;
      callbacks.onTransportChange("disconnected");
    },
  };
}
