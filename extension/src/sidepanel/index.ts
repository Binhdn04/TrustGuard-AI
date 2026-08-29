import type { AuthPublicState } from "../auth/public-state";
import type { AnalysisSnapshot } from "../api/client";
import { finalResultView } from "../analysis/final-result";
import {
  subscribeToAnalysisProgress,
  type AnalysisTransportState,
  type ProgressTransportApi,
} from "../analysis/event-stream";
import type { ProgressDisplay } from "../analysis/progress-selector";
import {
  internalMessageSchema,
  type ActiveAnalysisPublic,
  type CaptureEnvelope,
} from "../contracts/internal";
import { isTrustedExtensionSender } from "../runtime/sender";
import { buildCaseUrl, getBundledWebConfig } from "../web/config";
import "./styles.css";

const status = document.querySelector<HTMLElement>("#runtime-status");
const emptyState = document.querySelector<HTMLElement>("#empty-state");
const preview = document.querySelector<HTMLElement>("#capture-preview");
const captureKind = document.querySelector<HTMLElement>("#capture-kind");
const captureValue = document.querySelector<HTMLElement>("#capture-value");
const captureLength = document.querySelector<HTMLElement>("#capture-length");
const cancelButton = document.querySelector<HTMLButtonElement>("#cancel-capture");
const submitButton = document.querySelector<HTMLButtonElement>("#submit-analysis");
const externalConsent = document.querySelector<HTMLInputElement>("#consent-external");
const officialConsent = document.querySelector<HTMLInputElement>("#consent-official");
const submissionStatus = document.querySelector<HTMLElement>("#submission-status");
const authStateText = document.querySelector<HTMLElement>("#auth-state");
const authButton = document.querySelector<HTMLButtonElement>("#auth-action");
const analysisState = document.querySelector<HTMLElement>("#analysis-state");
const analysisStateCopy = document.querySelector<HTMLElement>("#analysis-state-copy");
const analysisId = document.querySelector<HTMLElement>("#analysis-id");
const analysisProgress = document.querySelector<HTMLElement>("#analysis-progress");
const analysisTransport = document.querySelector<HTMLElement>("#analysis-transport");
const finalResult = document.querySelector<HTMLElement>("#final-result");
const finalScope = document.querySelector<HTMLElement>("#final-scope");
const finalTitle = document.querySelector<HTMLElement>("#final-result-title");
const finalRisk = document.querySelector<HTMLElement>("#final-risk");
const finalRiskLabel = document.querySelector<HTMLElement>("#final-risk-label");
const finalScore = document.querySelector<HTMLElement>("#final-score");
const finalConfidence = document.querySelector<HTMLElement>("#final-confidence");
const finalSummary = document.querySelector<HTMLElement>("#final-summary");
const finalActionsBlock = document.querySelector<HTMLElement>("#final-actions-block");
const finalActions = document.querySelector<HTMLUListElement>("#final-actions");
const finalLimitationsBlock = document.querySelector<HTMLElement>("#final-limitations-block");
const finalLimitations = document.querySelector<HTMLUListElement>("#final-limitations");
const finalDegraded = document.querySelector<HTMLElement>("#final-degraded");
const openFullCase = document.querySelector<HTMLAnchorElement>("#open-full-case");
const webConfig = getBundledWebConfig();

let currentCapture: CaptureEnvelope | null = null;
let currentAuthState: AuthPublicState = { status: "signed_out" };
let submissionBusy = false;
let ambiguousInlineFailure = false;
let activeSubscription: { analysisId: string; stop(): void } | null = null;

class PanelTransportError extends Error {
  constructor(readonly code: string, readonly retryable: boolean) {
    super(code);
    this.name = "PanelTransportError";
  }
}

async function sendProgressMessage(message: unknown): Promise<ReturnType<typeof internalMessageSchema.parse>> {
  const response: unknown = await chrome.runtime.sendMessage(message);
  const parsed = internalMessageSchema.parse(response);
  if (parsed.type === "analysis.transport.error") {
    throw new PanelTransportError(parsed.code, parsed.retryable);
  }
  return parsed;
}

const progressApi: ProgressTransportApi = {
  async issueTicket(requestAnalysisId, cursor) {
    const parsed = await sendProgressMessage({
      type: "analysis.wsTicket.get",
      analysisId: requestAnalysisId,
      cursor,
    });
    if (parsed.type !== "analysis.wsTicket.issued" || parsed.analysisId !== requestAnalysisId) {
      throw new PanelTransportError("invalid_response", false);
    }
    return { url: parsed.url };
  },
  async getEvents(requestAnalysisId, cursor) {
    const parsed = await sendProgressMessage({
      type: "analysis.events.get",
      analysisId: requestAnalysisId,
      cursor,
    });
    if (parsed.type !== "analysis.events" || parsed.analysisId !== requestAnalysisId) {
      throw new PanelTransportError("invalid_response", false);
    }
    return { events: parsed.events, nextCursor: parsed.nextCursor };
  },
  async getSnapshot(requestAnalysisId) {
    const parsed = await sendProgressMessage({
      type: "analysis.snapshot.get",
      analysisId: requestAnalysisId,
    });
    if (parsed.type !== "analysis.snapshot" || parsed.analysis.analysisId !== requestAnalysisId) {
      throw new PanelTransportError("invalid_response", false);
    }
    return parsed.analysis;
  },
  async commitObservation(requestAnalysisId, observation) {
    const parsed = await sendProgressMessage({
      type: "analysis.observation.commit",
      analysisId: requestAnalysisId,
      ...observation,
    });
    if (parsed.type !== "analysis.observation" || parsed.analysis?.analysisId !== requestAnalysisId) {
      throw new PanelTransportError("storage_error", true);
    }
  },
};

function updateSubmitAvailability(): void {
  if (submitButton === null) return;
  submitButton.disabled =
    submissionBusy ||
    ambiguousInlineFailure ||
    currentCapture === null ||
    currentAuthState.status !== "signed_in";
}

function renderAuthState(state: AuthPublicState): void {
  currentAuthState = state;
  if (state.status !== "signed_in" && state.status !== "authenticating") {
    activeSubscription?.stop();
    activeSubscription = null;
    clearFinalResult();
  }
  if (authStateText === null || authButton === null) return;
  authButton.disabled = state.status === "authenticating" || state.status === "not_configured";
  authButton.hidden = state.status === "not_configured";
  if (state.status === "not_configured") {
    authStateText.textContent = "OIDC local chưa được cấu hình. Xem extension/.env.example.";
  } else if (state.status === "signed_in") {
    authStateText.textContent = "Đã đăng nhập. Token chỉ được giữ trong background session.";
    authButton.textContent = "Đăng xuất";
    void loadActiveAnalysis().catch(() => undefined);
  } else if (state.status === "authenticating") {
    authStateText.textContent = "Đang mở trang đăng nhập an toàn…";
    authButton.textContent = "Đang đăng nhập…";
  } else if (state.status === "error") {
    authStateText.textContent = state.code === "canceled"
      ? "Đăng nhập đã bị hủy."
      : "Không thể xác thực. Hãy kiểm tra cấu hình hoặc thử lại.";
    authButton.textContent = "Thử đăng nhập lại";
  } else {
    authStateText.textContent = "Đăng nhập bằng tài khoản TrustGuard để tiếp tục.";
    authButton.textContent = "Đăng nhập";
  }
  updateSubmitAvailability();
}

function resetRequestConsent(): void {
  if (externalConsent !== null) externalConsent.checked = false;
  if (officialConsent !== null) officialConsent.checked = false;
  if (submissionStatus !== null) submissionStatus.textContent = "";
  ambiguousInlineFailure = false;
}

function renderCapture(capture: CaptureEnvelope | null): void {
  const changed = currentCapture?.captureId !== capture?.captureId;
  currentCapture = capture;
  if (emptyState === null || preview === null) return;

  emptyState.hidden = capture !== null;
  preview.hidden = capture === null;
  if (changed) resetRequestConsent();
  if (capture === null) {
    if (captureValue !== null) captureValue.textContent = "";
    if (captureLength !== null) captureLength.textContent = "";
    updateSubmitAvailability();
    return;
  }

  if (captureKind !== null) {
    captureKind.textContent = capture.kind === "selection" ? "Đoạn văn bản đã chọn" : "Liên kết đã chọn";
  }
  if (captureValue !== null) captureValue.textContent = capture.value;
  if (captureLength !== null) {
    captureLength.textContent = `${[...capture.value].length.toLocaleString("vi-VN")} ký tự`;
  }
  updateSubmitAvailability();
}

function renderTransportState(transport: AnalysisTransportState): void {
  if (analysisTransport === null) return;
  const labels: Record<AnalysisTransportState, string> = {
    resuming: "Đang khôi phục tiến trình đã lưu…",
    connecting: "Đang kết nối kênh cập nhật…",
    connected: "Đang nhận cập nhật trực tiếp.",
    reconnecting: "Kết nối bị gián đoạn, đang kết nối lại…",
    polling_fallback: "Đang theo dõi bằng polling dự phòng.",
    disconnected: "Đã dừng theo dõi tiến trình.",
  };
  analysisTransport.textContent = labels[transport];
}

function renderProgress(progress: ProgressDisplay): void {
  if (analysisProgress !== null) analysisProgress.textContent = progress.label;
}

function renderTextList(element: HTMLUListElement | null, values: readonly string[]): void {
  if (element === null) return;
  element.replaceChildren(...values.map((value) => {
    const item = document.createElement("li");
    item.textContent = value;
    return item;
  }));
}

function clearFinalResult(): void {
  if (finalResult !== null) {
    finalResult.hidden = true;
    delete finalResult.dataset.tone;
  }
  if (openFullCase !== null) {
    openFullCase.hidden = true;
    openFullCase.removeAttribute("href");
  }
  renderTextList(finalActions, []);
  renderTextList(finalLimitations, []);
}

function renderTerminal(snapshot: AnalysisSnapshot): void {
  const view = finalResultView(snapshot);
  if (analysisProgress !== null) {
    analysisProgress.textContent = snapshot.status === "completed"
      ? "Phân tích đã hoàn tất; kết quả cuối đã được xác nhận."
      : "Phân tích đã kết thúc nhưng không tạo được kết quả hoàn chỉnh.";
  }
  if (analysisStateCopy !== null) {
    analysisStateCopy.textContent = snapshot.status === "completed"
      ? "Kết quả authoritative đã sẵn sàng và được hiển thị bên dưới."
      : "Backend xác nhận lượt phân tích đã thất bại. Tiến trình không được dùng làm kết luận rủi ro.";
  }
  if (
    view === null ||
    finalResult === null ||
    finalScope === null ||
    finalTitle === null ||
    finalSummary === null
  ) return;

  finalResult.hidden = false;
  finalResult.dataset.tone = view.tone;
  finalScope.textContent = view.scopeLabel;
  finalTitle.textContent = view.title;
  finalSummary.textContent = view.summary;
  if (finalRisk !== null) finalRisk.hidden = view.riskLabel === null;
  if (finalRiskLabel !== null) finalRiskLabel.textContent = view.riskLabel ?? "";
  if (finalScore !== null) finalScore.textContent = view.score === null ? "—" : `${view.score}/100`;
  if (finalConfidence !== null) {
    finalConfidence.textContent = view.confidencePercent === null ? "—" : `${view.confidencePercent}%`;
  }
  renderTextList(finalActions, view.actions);
  renderTextList(finalLimitations, view.limitations);
  if (finalActionsBlock !== null) finalActionsBlock.hidden = view.actions.length === 0;
  if (finalLimitationsBlock !== null) finalLimitationsBlock.hidden = view.limitations.length === 0;
  if (finalDegraded !== null) finalDegraded.hidden = !view.degraded;
  if (openFullCase !== null && webConfig !== null) {
    openFullCase.href = buildCaseUrl(webConfig, view.analysisId);
    openFullCase.hidden = false;
  }
  finalTitle.focus({ preventScroll: true });
}

function startProgressTracking(analysis: ActiveAnalysisPublic): void {
  if (activeSubscription?.analysisId === analysis.analysisId) return;
  activeSubscription?.stop();
  const subscription = subscribeToAnalysisProgress(progressApi, analysis, {
    onProgress: renderProgress,
    onStatus: (nextStatus) => {
      if (analysisStateCopy !== null && nextStatus === "running") {
        analysisStateCopy.textContent = "TrustGuard đang xử lý yêu cầu. Progress chỉ là trạng thái quan sát, chưa phải kết luận.";
      }
    },
    onTransportChange: renderTransportState,
    onTerminal: renderTerminal,
    onError: (error: unknown) => {
      if (error instanceof PanelTransportError && error.code === "reauth_required") {
        renderAuthState({ status: "signed_out" });
      }
      if (analysisTransport !== null) {
        analysisTransport.textContent = "Kênh cập nhật đang gián đoạn; kết quả backend vẫn là nguồn xác nhận cuối cùng.";
      }
    },
  });
  activeSubscription = { analysisId: analysis.analysisId, stop: () => subscription.stop() };
}

function renderAnalysisState(analysis: ActiveAnalysisPublic | null): void {
  if (analysisState === null || analysisStateCopy === null || analysisId === null) return;
  if (currentAuthState.status !== "signed_in") analysis = null;
  analysisState.hidden = analysis === null;
  if (analysis === null) {
    activeSubscription?.stop();
    activeSubscription = null;
    analysisStateCopy.textContent = "";
    if (analysisProgress !== null) analysisProgress.textContent = "";
    if (analysisTransport !== null) analysisTransport.textContent = "";
    analysisId.textContent = "";
    clearFinalResult();
    return;
  }
  if (activeSubscription?.analysisId !== analysis.analysisId) clearFinalResult();
  const mode = analysis.executionMode === "async" ? "xử lý nền" : "xử lý trực tiếp";
  const state = analysis.status === "completed" ? "đã hoàn tất" : "đã được tiếp nhận";
  analysisStateCopy.textContent = `Yêu cầu ${mode} ${state}. Progress không được dùng để suy ra verdict.`;
  if (analysisProgress !== null) analysisProgress.textContent = "Đang chuẩn bị theo dõi tiến trình…";
  analysisId.textContent = analysis.analysisId;
  if (currentAuthState.status === "signed_in") startProgressTracking(analysis);
  else if (analysisTransport !== null) analysisTransport.textContent = "Đăng nhập để tiếp tục theo dõi tiến trình.";
}

function submissionErrorMessage(code: string, retryable: boolean): string {
  if (code === "not_configured") return "API local chưa được cấu hình. Hãy đặt VITE_TRUSTGUARD_API_URL và build lại.";
  if (code === "reauth_required") return "Phiên đăng nhập không còn hợp lệ. Hãy đăng nhập lại trước khi gửi.";
  if (code === "forbidden") return "Tài khoản này không được phép tạo lượt phân tích.";
  if (code === "validation") return "Backend từ chối nội dung hoặc lựa chọn consent. Hãy hủy và tạo capture mới.";
  if (code === "rate_limited") return "Đã đạt giới hạn gửi. Hãy chờ rồi thử lại với cùng nội dung.";
  if (code === "conflict") return "Khóa gửi đã xung đột với nội dung khác. Hãy hủy và tạo capture mới.";
  if (code === "timeout" || code === "offline") {
    return retryable
      ? "Mất kết nối. Có thể thử lại; cùng nội dung sẽ dùng lại khóa gửi an toàn."
      : "Không xác định backend đã nhận yêu cầu inline hay chưa. Để tránh tạo case trùng, hãy kiểm tra lịch sử trên web trước khi capture lại.";
  }
  if (code === "stale_capture") return "Nội dung chờ gửi đã thay đổi hoặc hết hạn. Hãy chọn lại nội dung.";
  if (code === "stale_analysis") return "Lượt phân tích hiện tại đã thay đổi. Hãy mở lại Side Panel.";
  return "Không thể gửi yêu cầu an toàn. Hãy kiểm tra backend và thử lại.";
}

async function loadPendingCapture(): Promise<void> {
  const response: unknown = await chrome.runtime.sendMessage({ type: "capture.pending.get" });
  const parsed = internalMessageSchema.parse(response);
  if (parsed.type === "capture.pending") renderCapture(parsed.capture);
}

async function loadAuthState(): Promise<void> {
  const response: unknown = await chrome.runtime.sendMessage({ type: "auth.state.get" });
  const parsed = internalMessageSchema.parse(response);
  if (parsed.type === "auth.state") renderAuthState(parsed.state);
}

async function loadActiveAnalysis(): Promise<void> {
  const response: unknown = await chrome.runtime.sendMessage({ type: "analysis.active.get" });
  const parsed = internalMessageSchema.parse(response);
  if (parsed.type === "analysis.active") renderAnalysisState(parsed.analysis);
}

async function checkBackground(): Promise<void> {
  if (status === null) return;
  try {
    const response: unknown = await chrome.runtime.sendMessage({ type: "panel.ready" });
    const parsed = internalMessageSchema.parse(response);
    status.textContent = parsed.type === "panel.status" ? "Kết nối nội bộ: sẵn sàng" : "Kết nối nội bộ: lỗi";
    await Promise.all([loadPendingCapture(), loadAuthState(), loadActiveAnalysis()]);
  } catch {
    status.textContent = "Không thể kết nối background worker. Hãy reload extension.";
  }
}

authButton?.addEventListener("click", () => {
  const type = currentAuthState.status === "signed_in" ? "auth.logout" : "auth.login";
  if (type === "auth.login") renderAuthState({ status: "authenticating" });
  authButton.disabled = true;
  void chrome.runtime
    .sendMessage({ type })
    .then((response: unknown) => {
      const parsed = internalMessageSchema.parse(response);
      if (parsed.type === "auth.state") {
        renderAuthState(parsed.state);
      }
    })
    .catch(() => renderAuthState({ status: "error", code: "network" }));
});

submitButton?.addEventListener("click", () => {
  const capture = currentCapture;
  if (capture === null || submissionBusy || ambiguousInlineFailure) return;
  submissionBusy = true;
  if (submissionStatus !== null) submissionStatus.textContent = "Đang gửi nội dung đã xác nhận đến TrustGuard…";
  updateSubmitAvailability();
  void chrome.runtime
    .sendMessage({
      type: "analysis.create",
      captureId: capture.captureId,
      consent: {
        external_url_lookup: externalConsent?.checked === true,
        official_source_lookup: officialConsent?.checked === true,
      },
    })
    .then((response: unknown) => {
      const parsed = internalMessageSchema.parse(response);
      if (parsed.type === "analysis.submitted") {
        renderAnalysisState(parsed.analysis);
        if (currentCapture?.captureId === capture.captureId) renderCapture(null);
        else void loadPendingCapture();
        if (status !== null) status.textContent = "TrustGuard đã tiếp nhận yêu cầu.";
      } else if (parsed.type === "analysis.error") {
        ambiguousInlineFailure =
          (parsed.code === "timeout" || parsed.code === "offline") && !parsed.retryable;
        if (parsed.code === "reauth_required") renderAuthState({ status: "signed_out" });
        if (submissionStatus !== null) {
          submissionStatus.textContent = submissionErrorMessage(parsed.code, parsed.retryable);
        }
      }
    })
    .catch(() => {
      ambiguousInlineFailure = true;
      if (submissionStatus !== null) {
        submissionStatus.textContent = "Mất kết nối với background worker. Không tự động gửi lại để tránh tạo case trùng.";
      }
    })
    .finally(() => {
      submissionBusy = false;
      updateSubmitAvailability();
    });
});

cancelButton?.addEventListener("click", () => {
  const capture = currentCapture;
  if (capture === null) return;
  void chrome.runtime
    .sendMessage({ type: "capture.pending.clear", captureId: capture.captureId })
    .then((response: unknown) => {
      const parsed = internalMessageSchema.parse(response);
      if (
        parsed.type === "capture.pending.cleared" &&
        parsed.captureId === capture.captureId &&
        parsed.cleared
      ) {
        renderCapture(null);
      } else {
        void loadPendingCapture();
      }
    })
    .catch(() => {
      if (status !== null) status.textContent = "Không thể hủy nội dung. Hãy thử lại.";
    });
});

chrome.runtime.onMessage.addListener((rawMessage: unknown, sender) => {
  if (!isTrustedExtensionSender(sender, chrome.runtime.id)) return false;
  const parsed = internalMessageSchema.safeParse(rawMessage);
  if (!parsed.success) return false;
  if (parsed.data.type === "capture.preview") renderCapture(parsed.data.capture);
  if (parsed.data.type === "capture.pending") renderCapture(parsed.data.capture);
  if (parsed.data.type === "auth.state") renderAuthState(parsed.data.state);
  if (parsed.data.type === "analysis.active") renderAnalysisState(parsed.data.analysis);
  return false;
});

void checkBackground();

window.addEventListener("pagehide", () => activeSubscription?.stop(), { once: true });
