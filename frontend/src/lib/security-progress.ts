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
  return SECURITY_PROGRESS_LABELS[stage].started ?? GENERIC_PROGRESS_LABEL;
}
