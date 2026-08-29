import {
  MAX_CAPTURE_CHARACTERS,
  captureEnvelopeSchema,
  type CaptureEnvelope,
} from "../contracts/internal";

export const SELECTION_CONTEXT_MENU_ID = "trustguard.capture.selection";
export const LINK_CONTEXT_MENU_ID = "trustguard.capture.link";
export const CAPTURE_CONTEXT_MENU_ITEMS = [
  {
    id: SELECTION_CONTEXT_MENU_ID,
    title: "Analyze selected text with TrustGuard",
    contexts: ["selection"],
  },
  {
    id: LINK_CONTEXT_MENU_ID,
    title: "Analyze link with TrustGuard",
    contexts: ["link"],
  },
] as const;

export type CaptureErrorCode =
  | "unsupported-action"
  | "missing-input"
  | "empty-input"
  | "oversized-input"
  | "unsafe-link";

export class CaptureInputError extends Error {
  constructor(readonly code: CaptureErrorCode) {
    super(code);
    this.name = "CaptureInputError";
  }
}

export interface ContextMenuCaptureInput {
  menuItemId: string | number;
  selectionText?: string;
  linkUrl?: string;
  frameId?: number;
}

export interface CaptureFactoryDependencies {
  now?: () => Date;
  randomUUID?: () => string;
}

function ensureBounded(value: string): string {
  if (value.length === 0) {
    throw new CaptureInputError("empty-input");
  }
  if ([...value].length > MAX_CAPTURE_CHARACTERS) {
    throw new CaptureInputError("oversized-input");
  }
  return value;
}

export function normalizeSelectionText(rawValue: string | undefined): string {
  if (rawValue === undefined) {
    throw new CaptureInputError("missing-input");
  }
  return ensureBounded(rawValue.normalize("NFC").replaceAll("\r\n", "\n").replaceAll("\r", "\n").trim());
}

export function normalizeLinkUrl(rawValue: string | undefined): string {
  if (rawValue === undefined) {
    throw new CaptureInputError("missing-input");
  }
  const value = ensureBounded(rawValue.normalize("NFC").trim());
  if (/\s/u.test(value)) {
    throw new CaptureInputError("unsafe-link");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new CaptureInputError("unsafe-link");
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.hostname.length === 0 ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.hash.length > 0
  ) {
    throw new CaptureInputError("unsafe-link");
  }
  return ensureBounded(url.href);
}

export function createCaptureFromContextMenu(
  input: ContextMenuCaptureInput,
  dependencies: CaptureFactoryDependencies = {},
): CaptureEnvelope {
  const now = dependencies.now ?? (() => new Date());
  const randomUUID = dependencies.randomUUID ?? (() => crypto.randomUUID());
  const common = {
    version: 1 as const,
    captureId: randomUUID(),
    createdAt: now().toISOString(),
    source: "context-menu" as const,
  };

  if (input.menuItemId === SELECTION_CONTEXT_MENU_ID) {
    return captureEnvelopeSchema.parse({
      ...common,
      kind: "selection",
      value: normalizeSelectionText(input.selectionText),
    });
  }
  if (input.menuItemId === LINK_CONTEXT_MENU_ID) {
    return captureEnvelopeSchema.parse({
      ...common,
      kind: "link",
      value: normalizeLinkUrl(input.linkUrl),
    });
  }
  throw new CaptureInputError("unsupported-action");
}
