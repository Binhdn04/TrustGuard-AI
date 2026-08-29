import type { AuthPublicState } from "../auth/public-state";
import { internalMessageSchema, type CaptureEnvelope } from "../contracts/internal";
import { isTrustedExtensionSender } from "../runtime/sender";
import "./styles.css";

const status = document.querySelector<HTMLElement>("#runtime-status");
const emptyState = document.querySelector<HTMLElement>("#empty-state");
const preview = document.querySelector<HTMLElement>("#capture-preview");
const captureKind = document.querySelector<HTMLElement>("#capture-kind");
const captureValue = document.querySelector<HTMLElement>("#capture-value");
const captureLength = document.querySelector<HTMLElement>("#capture-length");
const cancelButton = document.querySelector<HTMLButtonElement>("#cancel-capture");
const authStateText = document.querySelector<HTMLElement>("#auth-state");
const authButton = document.querySelector<HTMLButtonElement>("#auth-action");

let currentCapture: CaptureEnvelope | null = null;
let currentAuthState: AuthPublicState = { status: "signed_out" };

function renderAuthState(state: AuthPublicState): void {
  currentAuthState = state;
  if (authStateText === null || authButton === null) return;
  authButton.disabled = state.status === "authenticating" || state.status === "not_configured";
  authButton.hidden = state.status === "not_configured";
  if (state.status === "not_configured") {
    authStateText.textContent = "OIDC local chưa được cấu hình. Xem extension/.env.example.";
  } else if (state.status === "signed_in") {
    authStateText.textContent = "Đã đăng nhập. Token chỉ được giữ trong background session.";
    authButton.textContent = "Đăng xuất";
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
}

function renderCapture(capture: CaptureEnvelope | null): void {
  currentCapture = capture;
  if (emptyState === null || preview === null) return;

  emptyState.hidden = capture !== null;
  preview.hidden = capture === null;
  if (capture === null) {
    if (captureValue !== null) captureValue.textContent = "";
    if (captureLength !== null) captureLength.textContent = "";
    return;
  }

  if (captureKind !== null) {
    captureKind.textContent = capture.kind === "selection" ? "Đoạn văn bản đã chọn" : "Liên kết đã chọn";
  }
  if (captureValue !== null) captureValue.textContent = capture.value;
  if (captureLength !== null) {
    captureLength.textContent = `${[...capture.value].length.toLocaleString("vi-VN")} ký tự`;
  }
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

async function checkBackground(): Promise<void> {
  if (status === null) return;
  try {
    const response: unknown = await chrome.runtime.sendMessage({ type: "panel.ready" });
    const parsed = internalMessageSchema.parse(response);
    status.textContent = parsed.type === "panel.status" ? "Kết nối nội bộ: sẵn sàng" : "Kết nối nội bộ: lỗi";
    await Promise.all([loadPendingCapture(), loadAuthState()]);
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
      if (parsed.type === "auth.state") renderAuthState(parsed.state);
    })
    .catch(() => renderAuthState({ status: "error", code: "network" }));
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
  return false;
});

void checkBackground();
