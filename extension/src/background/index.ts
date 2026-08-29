import { getBundledOidcConfig } from "../auth/config";
import { AuthFlowError, OidcAuthManager } from "../auth/oidc";
import type { AuthPublicState } from "../auth/public-state";
import { AuthSessionStore } from "../auth/session-store";
import {
  CAPTURE_CONTEXT_MENU_ITEMS,
  createCaptureFromContextMenu,
} from "../capture/normalize";
import { PendingCaptureStore, SerialTaskQueue } from "../capture/pending-store";
import {
  internalMessageSchema,
  type CaptureEnvelope,
  type InternalMessage,
} from "../contracts/internal";
import { isTrustedSidePanelSender } from "../runtime/sender";

const pendingCaptures = new PendingCaptureStore(chrome.storage.session);
const authStore = new AuthSessionStore(chrome.storage.session);
const auth = new OidcAuthManager({
  config: getBundledOidcConfig(),
  store: authStore,
  identity: chrome.identity,
});
const captureQueue = new SerialTaskQueue();
const sidePanelUrl = chrome.runtime.getURL("sidepanel.html");

async function enableActionToOpenSidePanel(): Promise<void> {
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
}

async function restrictSessionStorage(): Promise<void> {
  await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
}

function removeAllContextMenus(): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.contextMenus.removeAll(() => {
      const error = chrome.runtime.lastError;
      if (error === undefined) resolve();
      else reject(new Error(error.message));
    });
  });
}

function createContextMenu(properties: chrome.contextMenus.CreateProperties): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.contextMenus.create(properties, () => {
      const error = chrome.runtime.lastError;
      if (error === undefined) resolve();
      else reject(new Error(error.message));
    });
  });
}

async function registerContextMenus(): Promise<void> {
  await removeAllContextMenus();
  for (const item of CAPTURE_CONTEXT_MENU_ITEMS) {
    await createContextMenu({ ...item, contexts: [...item.contexts] });
  }
}

function openSidePanel(tab: chrome.tabs.Tab | undefined): Promise<boolean> {
  if (tab?.windowId !== undefined) {
    return chrome.sidePanel.open({ windowId: tab.windowId }).then(
      () => true,
      () => false,
    );
  }
  return Promise.resolve(false);
}

async function notifyPanel(message: InternalMessage): Promise<void> {
  try {
    await chrome.runtime.sendMessage(message);
  } catch {
    // The panel may still be opening. It reads the same state from storage.session on startup.
  }
}

async function commitContextMenuCapture(
  capture: CaptureEnvelope | null,
  panelOpening: Promise<boolean>,
): Promise<void> {
  try {
    if (capture === null) await pendingCaptures.clear();
    else await pendingCaptures.save(capture);
  } catch {
    await pendingCaptures.clear();
    capture = null;
  }
  if (!(await panelOpening)) return;
  if (capture === null) await notifyPanel({ type: "capture.pending", capture: null });
  else await notifyPanel({ type: "capture.preview", capture });
}

void enableActionToOpenSidePanel();
void restrictSessionStorage();

chrome.runtime.onInstalled.addListener(() => {
  void authStore.clearAll();
  void enableActionToOpenSidePanel();
  void restrictSessionStorage();
  void registerContextMenus();
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let capture: CaptureEnvelope | null = null;
  try {
    capture = createCaptureFromContextMenu(info);
  } catch {
    // Invalid input is never persisted or forwarded to the Side Panel.
  }
  const panelOpening = openSidePanel(tab);
  void captureQueue.run(() => commitContextMenuCapture(capture, panelOpening));
});

chrome.runtime.onMessage.addListener((rawMessage: unknown, sender, sendResponse) => {
  if (!isTrustedSidePanelSender(sender, chrome.runtime.id, sidePanelUrl)) {
    return false;
  }
  const result = internalMessageSchema.safeParse(rawMessage);
  if (!result.success) {
    return false;
  }

  if (result.data.type === "panel.ready") {
    sendResponse({ type: "panel.status", status: "ready" } satisfies InternalMessage);
    return false;
  }
  if (result.data.type === "auth.state.get") {
    void auth.publicState().then((state) => {
      sendResponse({ type: "auth.state", state } satisfies InternalMessage);
    });
    return true;
  }
  if (result.data.type === "auth.login") {
    void auth.login().then(
      (state) => sendResponse({ type: "auth.state", state } satisfies InternalMessage),
      (error: unknown) => {
        const state: AuthPublicState = {
          status: "error",
          code: error instanceof AuthFlowError ? error.code : "network",
        };
        sendResponse({ type: "auth.state", state } satisfies InternalMessage);
      },
    );
    return true;
  }
  if (result.data.type === "auth.logout") {
    void auth.logout().then((state) => {
      sendResponse({ type: "auth.state", state } satisfies InternalMessage);
    });
    return true;
  }
  if (result.data.type === "capture.pending.get") {
    void pendingCaptures.read().then((capture) => {
      sendResponse({ type: "capture.pending", capture } satisfies InternalMessage);
    });
    return true;
  }
  if (result.data.type === "capture.pending.clear") {
    const captureId = result.data.captureId;
    void pendingCaptures.clearIfMatching(captureId).then((cleared) => {
      sendResponse({ type: "capture.pending.cleared", captureId, cleared } satisfies InternalMessage);
    });
    return true;
  }
  return false;
});
