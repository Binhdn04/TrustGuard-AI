import { describe, expect, it } from "vitest";

import {
  CAPTURE_CONTEXT_MENU_ITEMS,
  CaptureInputError,
  LINK_CONTEXT_MENU_ID,
  SELECTION_CONTEXT_MENU_ID,
  createCaptureFromContextMenu,
  normalizeLinkUrl,
  normalizeSelectionText,
} from "../src/capture/normalize";

const fixedDependencies = {
  now: () => new Date("2026-08-29T10:00:00.000Z"),
  randomUUID: () => "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e",
};

function expectCaptureError(action: () => unknown, code: CaptureInputError["code"]): void {
  try {
    action();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(CaptureInputError);
    if (error instanceof CaptureInputError) expect(error.code).toBe(code);
    return;
  }
  throw new Error(`Expected CaptureInputError with code ${code}.`);
}

describe("selection capture boundary", () => {
  it("defines exactly one selection menu and one link menu", () => {
    expect(CAPTURE_CONTEXT_MENU_ITEMS).toEqual([
      expect.objectContaining({ id: SELECTION_CONTEXT_MENU_ID, contexts: ["selection"] }),
      expect.objectContaining({ id: LINK_CONTEXT_MENU_ID, contexts: ["link"] }),
    ]);
  });

  it("normalizes Unicode, line endings and surrounding whitespace", () => {
    expect(normalizeSelectionText(" \r\nCafe\u0301\u00a0 \r\n")).toBe("Café");
  });

  it("accepts exactly 5,000 Unicode characters and rejects 5,001", () => {
    expect([...normalizeSelectionText("🛡️".repeat(2_500))]).toHaveLength(5_000);
    expectCaptureError(
      () => normalizeSelectionText("🛡️".repeat(2_500) + "x"),
      "oversized-input",
    );
  });

  it("captures iframe selection without collecting frame or page metadata", () => {
    const capture = createCaptureFromContextMenu(
      {
        menuItemId: SELECTION_CONTEXT_MENU_ID,
        selectionText: "  Verify this OTP request  ",
        frameId: 7,
      },
      fixedDependencies,
    );

    expect(capture).toEqual({
      version: 1,
      captureId: fixedDependencies.randomUUID(),
      kind: "selection",
      value: "Verify this OTP request",
      createdAt: fixedDependencies.now().toISOString(),
      source: "context-menu",
    });
    expect(capture).not.toHaveProperty("frameId");
    expect(capture).not.toHaveProperty("pageUrl");
  });

  it.each([undefined, "", " \n\t\u00a0 "])("rejects missing or empty selection %s", (value) => {
    expect(() => normalizeSelectionText(value)).toThrow(CaptureInputError);
  });
});

describe("link capture boundary", () => {
  it("normalizes an explicit safe HTTP(S) link", () => {
    const capture = createCaptureFromContextMenu(
      { menuItemId: LINK_CONTEXT_MENU_ID, linkUrl: " HTTPS://EXAMPLE.TEST/path?q=1 " },
      fixedDependencies,
    );
    expect(capture).toMatchObject({
      kind: "link",
      value: "https://example.test/path?q=1",
    });
  });

  it.each([
    "javascript:alert(1)",
    "data:text/html,unsafe",
    "file:///etc/passwd",
    "chrome://settings",
    "https://user:secret@example.test/login",
    "https://example.test/login#token",
    "https://example.test/a path",
    "example.test/login",
  ])("rejects unsafe link %s", (value) => {
    expectCaptureError(() => normalizeLinkUrl(value), "unsafe-link");
  });
});
