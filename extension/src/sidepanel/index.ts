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

let currentCapture: CaptureEnvelope | null = null;

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

async function checkBackground(): Promise<void> {
  if (status === null) return;
  try {
    const response: unknown = await chrome.runtime.sendMessage({ type: "panel.ready" });
    const parsed = internalMessageSchema.parse(response);
    status.textContent = parsed.type === "panel.status" ? "Kết nối nội bộ: sẵn sàng" : "Kết nối nội bộ: lỗi";
    await loadPendingCapture();
  } catch {
    status.textContent = "Không thể kết nối background worker. Hãy reload extension.";
  }
}

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
  return false;
});

void checkBackground();
