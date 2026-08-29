import { z } from "zod";

import type { AnalysisEventPublic, ActiveAnalysisPublic } from "../contracts/internal";

export const SECURITY_PROGRESS_STAGES = [
  "running",
  "understanding",
  "scope_gate",
  "incident_response",
  "investigation",
  "official_link_verification",
  "security_memory_lookup",
  "risk_assessment",
  "assistant_response",
] as const;

export type SecurityProgressStage = (typeof SECURITY_PROGRESS_STAGES)[number];
export type SecurityProgressState = "started" | "completed" | "skipped" | "degraded";

const GENERIC_PROGRESS_LABEL = "Đang tiếp tục kiểm tra nội dung";
const LABELS: Readonly<Record<SecurityProgressStage, Readonly<Partial<Record<SecurityProgressState, string>>>>> = {
  running: { started: "Đang chuẩn bị phiên kiểm tra" },
  understanding: {
    started: "Đang phân tích ngữ cảnh bảo mật",
    completed: "Đã hoàn tất phân tích ngữ cảnh bảo mật",
    degraded: "Dữ liệu phân tích ngữ cảnh bảo mật bị giới hạn",
  },
  scope_gate: { completed: "Đã xác định phạm vi kiểm tra" },
  incident_response: {
    started: "Đang chuẩn bị hướng dẫn xử lý sự cố",
    completed: "Đã hoàn tất hướng dẫn xử lý sự cố",
  },
  investigation: {
    started: "Đang kiểm tra các tín hiệu liên quan",
    completed: "Đã hoàn tất kiểm tra các tín hiệu liên quan",
    skipped: "Một phần kiểm tra đã được bỏ qua theo chính sách hiện hành",
    degraded: "Dữ liệu kiểm tra các tín hiệu liên quan bị giới hạn",
  },
  official_link_verification: {
    started: "Đang đối chiếu với nguồn chính thức",
    completed: "Đã hoàn tất đối chiếu nguồn chính thức",
    skipped: "Đối chiếu nguồn chính thức không được thực hiện",
    degraded: "Dữ liệu đối chiếu nguồn chính thức bị giới hạn",
  },
  security_memory_lookup: {
    started: "Đang đối chiếu thông tin an toàn đã được duyệt",
    completed: "Đã hoàn tất đối chiếu thông tin an toàn đã được duyệt",
  },
  risk_assessment: {
    started: "Đang tổng hợp đánh giá rủi ro",
    completed: "Đã hoàn tất tổng hợp đánh giá rủi ro",
  },
  assistant_response: {
    started: "Đang chuẩn bị hướng dẫn ngắn gọn",
    completed: "Đã hoàn tất chuẩn bị hướng dẫn",
    degraded: "Hướng dẫn tạm thời bị giới hạn",
  },
};

const webSocketEventSchema = z.object({
  event_id: z.uuid(),
  analysis_id: z.uuid(),
  sequence: z.number().int().positive(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  step: z.string().min(1).max(200),
  kind: z.enum(["status", "provisional", "progress", "final"]),
  progress_state: z.enum(["started", "completed", "skipped", "degraded"]).nullable().optional(),
  occurred_at: z.iso.datetime({ offset: true }),
}).passthrough();

export interface ProgressDisplay {
  eventId: string;
  sequence: number;
  stage: SecurityProgressStage | null;
  state: SecurityProgressState | null;
  label: string;
}

export interface ProgressCursorState {
  cursor: string | null;
  lastSequence: number;
  status: ActiveAnalysisPublic["status"];
}

export interface ProgressReduction extends ProgressCursorState {
  latest: ProgressDisplay | null;
  terminal: boolean;
  advanced: boolean;
}

export function parseWebSocketEvent(value: unknown): AnalysisEventPublic | null {
  const parsed = webSocketEventSchema.safeParse(value);
  if (!parsed.success) return null;
  return {
    eventId: parsed.data.event_id,
    analysisId: parsed.data.analysis_id,
    sequence: parsed.data.sequence,
    status: parsed.data.status,
    step: parsed.data.step,
    kind: parsed.data.kind,
    progressState: parsed.data.progress_state ?? null,
    occurredAt: parsed.data.occurred_at,
  };
}

export function cursorForSequence(sequence: number): string {
  return btoa(String(sequence)).replace(/=+$/u, "").replace(/\+/gu, "-").replace(/\//gu, "_");
}

function isStage(value: string): value is SecurityProgressStage {
  return (SECURITY_PROGRESS_STAGES as readonly string[]).includes(value);
}

function displayFor(event: AnalysisEventPublic): ProgressDisplay | null {
  if (event.kind !== "progress") return null;
  const stage = isStage(event.step) ? event.step : null;
  const state = event.progressState;
  return {
    eventId: event.eventId,
    sequence: event.sequence,
    stage,
    state,
    label: stage !== null && state !== null ? LABELS[stage][state] ?? GENERIC_PROGRESS_LABEL : GENERIC_PROGRESS_LABEL,
  };
}

export function reduceAnalysisEvents(
  analysisId: string,
  current: ProgressCursorState,
  events: readonly AnalysisEventPublic[],
  seenEventIds: Set<string>,
  pageCursor: string | null = null,
): ProgressReduction {
  const ordered = [...events]
    .filter((event) => event.analysisId === analysisId && !seenEventIds.has(event.eventId))
    .sort((left, right) => left.sequence - right.sequence || left.eventId.localeCompare(right.eventId));
  let lastSequence = current.lastSequence;
  let cursor = current.cursor;
  let status = current.status;
  let latest: ProgressDisplay | null = null;
  let terminal = status === "completed" || status === "failed";
  let advanced = false;

  for (const event of ordered) {
    seenEventIds.add(event.eventId);
    if (event.sequence <= lastSequence) continue;
    lastSequence = event.sequence;
    cursor = cursorForSequence(event.sequence);
    status = event.status;
    terminal = terminal || event.kind === "final" || status === "completed" || status === "failed";
    latest = displayFor(event) ?? latest;
    advanced = true;
  }
  if (pageCursor !== null && (advanced || pageCursor !== current.cursor)) cursor = pageCursor;
  return { cursor, lastSequence, status, latest, terminal, advanced };
}
