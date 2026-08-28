import type { SecurityAnalysisEventV4 } from "@/types/generated/api-v4";

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

type SecurityProgressLabels = Readonly<Partial<Record<SecurityProgressState, string>>>;

const GENERIC_PROGRESS_LABEL = "Đang tiếp tục kiểm tra nội dung";

export const SECURITY_PROGRESS_LABELS: Readonly<Record<SecurityProgressStage, SecurityProgressLabels>> = {
  running: { started: "Đang chuẩn bị phiên kiểm tra" },
  understanding: {
    started: "Đang phân tích ngữ cảnh bảo mật",
    completed: "Đã hoàn tất phân tích ngữ cảnh bảo mật",
    degraded: "Dữ liệu phân tích ngữ cảnh bảo mật bị giới hạn",
  },
  scope_gate: {
    completed: "Đã xác định phạm vi kiểm tra",
  },
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

export function isSecurityProgressStage(value: string): value is SecurityProgressStage {
  return (SECURITY_PROGRESS_STAGES as readonly string[]).includes(value);
}

export function securityProgressLabel(stage: string, state?: string | null): string {
  if (!isSecurityProgressStage(stage)) {
    return GENERIC_PROGRESS_LABEL;
  }
  if (state === "started" || state === "completed" || state === "skipped" || state === "degraded") {
    return SECURITY_PROGRESS_LABELS[stage][state] ?? GENERIC_PROGRESS_LABEL;
  }
  return GENERIC_PROGRESS_LABEL;
}

export interface SecurityProgressDisplay {
  eventId: string;
  analysisId: string;
  sequence: number;
  stage: SecurityProgressStage | null;
  state: SecurityProgressState | null;
  label: string;
}

export interface SecurityProgressViewModel {
  latest: SecurityProgressDisplay | null;
  timeline: SecurityProgressDisplay[];
}

type EventLike = Partial<SecurityAnalysisEventV4> | Record<string, unknown>;

function isRecord(value: unknown): value is EventLike {
  return typeof value === "object" && value !== null;
}

function isProgressState(value: unknown): value is SecurityProgressState {
  return value === "started" || value === "completed" || value === "skipped" || value === "degraded";
}

function displayFor(event: EventLike, activeAnalysisId: string): SecurityProgressDisplay | null {
  const sequence = event.sequence;
  if (
    event.analysis_id !== activeAnalysisId
    || event.kind !== "progress"
    || typeof event.event_id !== "string"
    || !event.event_id
    || typeof sequence !== "number"
    || !Number.isSafeInteger(sequence)
    || sequence < 1
  ) {
    return null;
  }
  const stage = typeof event.step === "string" && isSecurityProgressStage(event.step) ? event.step : null;
  const state = isProgressState(event.progress_state) ? event.progress_state : null;
  return {
    eventId: event.event_id,
    analysisId: activeAnalysisId,
    sequence,
    stage,
    state,
    label: stage && state ? securityProgressLabel(stage, state) : GENERIC_PROGRESS_LABEL,
  };
}

/**
 * Produces display-only progress for the currently active analysis.
 *
 * Cursor polling and WebSocket replay can overlap. We dedupe by event ID and
 * always choose the greatest sequence, so a replay or delayed event cannot
 * move the busy state backwards. Event payload text, evidence and risk hints
 * are intentionally outside this selector's input surface.
 */
export function selectSecurityProgress(
  activeAnalysisId: string | null,
  events: readonly unknown[],
): SecurityProgressViewModel {
  if (!activeAnalysisId) return { latest: null, timeline: [] };

  const byEventId = new Map<string, SecurityProgressDisplay>();
  for (const value of events) {
    if (!isRecord(value)) continue;
    const display = displayFor(value, activeAnalysisId);
    if (!display) continue;
    const existing = byEventId.get(display.eventId);
    if (!existing || display.sequence > existing.sequence) byEventId.set(display.eventId, display);
  }

  const ordered = [...byEventId.values()].sort((left, right) => (
    left.sequence - right.sequence || left.eventId.localeCompare(right.eventId)
  ));
  const timeline = ordered.filter((entry) => entry.stage !== null && entry.state !== null);
  return { latest: ordered.at(-1) ?? null, timeline };
}
