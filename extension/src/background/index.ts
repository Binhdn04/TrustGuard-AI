import { getBundledOidcConfig } from "../auth/config";
import { AuthFlowError, OidcAuthManager } from "../auth/oidc";
import type { AuthPublicState } from "../auth/public-state";
import { AuthSessionStore } from "../auth/session-store";
import { HttpTrustGuardAnalysisApi, TrustGuardApiError } from "../api/client";
import { buildWebSocketStreamUrl, getBundledApiConfig } from "../api/config";
import { ActiveAnalysisStore, SubmissionAttemptStore } from "../analysis/session-store";
import { AnalysisSubmissionService } from "../analysis/submission";
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
const apiConfig = getBundledApiConfig();
const analysisApi = apiConfig === null ? null : new HttpTrustGuardAnalysisApi(apiConfig);
const activeAnalyses = new ActiveAnalysisStore(chrome.storage.session);
const submissionAttempts = new SubmissionAttemptStore(chrome.storage.session);
const submissions = new AnalysisSubmissionService({
  api: analysisApi,
  auth,
  pendingCaptures,
  activeAnalyses,
  attempts: submissionAttempts,
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

function publicAnalysisState(state: Awaited<ReturnType<ActiveAnalysisStore["read"]>>) {
  if (state === null) return null;
  return {
    analysisId: state.analysisId,
    executionMode: state.executionMode,
    status: state.status,
    cursor: state.cursor,
    lastSequence: state.lastSequence,
    createdAt: state.createdAt,
    observedAt: state.observedAt,
  };
}

function progressFailure(error: unknown): TrustGuardApiError {
  if (error instanceof TrustGuardApiError) return error;
  if (error instanceof AuthFlowError) {
    return new TrustGuardApiError(
      error.code === "not_configured" ? "not_configured" : "reauth_required",
      false,
      0,
    );
  }
  return new TrustGuardApiError("storage_error", true, 0);
}

async function requireCurrentAnalysis(analysisId: string) {
  const state = await activeAnalyses.read();
  if (state === null || state.analysisId !== analysisId) {
    throw new TrustGuardApiError("stale_analysis", false, 0);
  }
  return state;
}

async function sendTransportFailure(
  analysisId: string,
  error: unknown,
  sendResponse: (response?: unknown) => void,
): Promise<void> {
  const failure = progressFailure(error);
  if (failure.code === "reauth_required") await authStore.clearAll();
  sendResponse({
    type: "analysis.transport.error",
    analysisId,
    code: failure.code,
    retryable: failure.retryable,
  } satisfies InternalMessage);
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
    void pendingCaptures.clearIfMatching(captureId).then(async (cleared) => {
      if (cleared) await submissionAttempts.clearIfMatching(captureId);
      sendResponse({ type: "capture.pending.cleared", captureId, cleared } satisfies InternalMessage);
    });
    return true;
  }
  if (result.data.type === "analysis.active.get") {
    void activeAnalyses.read().then((state) => {
      sendResponse({
        type: "analysis.active",
        analysis: publicAnalysisState(state),
      } satisfies InternalMessage);
    });
    return true;
  }
  if (result.data.type === "analysis.create") {
    const { captureId, consent } = result.data;
    void submissions.submit(captureId, consent).then(
      (state) => {
        sendResponse({
          type: "analysis.submitted",
          analysis: publicAnalysisState(state)!,
        } satisfies InternalMessage);
      },
      async (error: unknown) => {
        const failure = error instanceof TrustGuardApiError
          ? error
          : new TrustGuardApiError("storage_error", true, 0);
        if (failure.code === "reauth_required") await authStore.clearAll();
        sendResponse({
          type: "analysis.error",
          code: failure.code,
          retryable: failure.retryable,
        } satisfies InternalMessage);
      },
    );
    return true;
  }
  if (result.data.type === "analysis.wsTicket.get") {
    const { analysisId, cursor } = result.data;
    void (async () => {
      try {
        await requireCurrentAnalysis(analysisId);
        if (analysisApi === null || apiConfig === null) {
          throw new TrustGuardApiError("not_configured", false, 0);
        }
        const accessToken = await auth.getValidAccessToken();
        const ticket = await analysisApi.createWebSocketTicket(analysisId, accessToken);
        sendResponse({
          type: "analysis.wsTicket.issued",
          analysisId,
          url: buildWebSocketStreamUrl(
            apiConfig,
            analysisId,
            ticket.streamPath,
            ticket.ticket,
            cursor,
          ),
          expiresAt: ticket.expiresAt,
        } satisfies InternalMessage);
      } catch (error: unknown) {
        await sendTransportFailure(analysisId, error, sendResponse);
      }
    })();
    return true;
  }
  if (result.data.type === "analysis.events.get") {
    const { analysisId, cursor } = result.data;
    void (async () => {
      try {
        await requireCurrentAnalysis(analysisId);
        if (analysisApi === null) throw new TrustGuardApiError("not_configured", false, 0);
        const accessToken = await auth.getValidAccessToken();
        const page = await analysisApi.getAnalysisEvents(analysisId, cursor, accessToken);
        sendResponse({
          type: "analysis.events",
          analysisId,
          events: page.events,
          nextCursor: page.nextCursor,
        } satisfies InternalMessage);
      } catch (error: unknown) {
        await sendTransportFailure(analysisId, error, sendResponse);
      }
    })();
    return true;
  }
  if (result.data.type === "analysis.snapshot.get") {
    const { analysisId } = result.data;
    void (async () => {
      try {
        const current = await requireCurrentAnalysis(analysisId);
        if (analysisApi === null) throw new TrustGuardApiError("not_configured", false, 0);
        const accessToken = await auth.getValidAccessToken();
        const snapshot = await analysisApi.getAnalysis(analysisId, accessToken);
        await activeAnalyses.observe(analysisId, {
          cursor: current.cursor,
          lastSequence: current.lastSequence,
          status: snapshot.status,
        });
        sendResponse({ type: "analysis.snapshot", analysis: snapshot } satisfies InternalMessage);
      } catch (error: unknown) {
        await sendTransportFailure(analysisId, error, sendResponse);
      }
    })();
    return true;
  }
  if (result.data.type === "analysis.observation.commit") {
    const { analysisId, cursor, lastSequence, status: observedStatus } = result.data;
    void activeAnalyses.observe(analysisId, {
      cursor,
      lastSequence,
      status: observedStatus,
    }).then(
      (state) => sendResponse({
        type: "analysis.observation",
        analysis: publicAnalysisState(state),
      } satisfies InternalMessage),
      (error: unknown) => sendTransportFailure(analysisId, error, sendResponse),
    );
    return true;
  }
  return false;
});
