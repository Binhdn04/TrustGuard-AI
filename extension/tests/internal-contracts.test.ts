import { describe, expect, it } from "vitest";

import { captureEnvelopeSchema, internalMessageSchema } from "../src/contracts/internal";

const baseCapture = {
  version: 1,
  captureId: "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e",
  createdAt: "2026-08-29T10:00:00+07:00",
  source: "context-menu",
} as const;

describe("capture envelope", () => {
  it("accepts only the explicit selection payload", () => {
    const parsed = captureEnvelopeSchema.parse({
      ...baseCapture,
      kind: "selection",
      value: "Ngân hàng yêu cầu cung cấp OTP",
    });
    expect(Object.keys(parsed).sort()).toEqual([
      "captureId",
      "createdAt",
      "kind",
      "source",
      "value",
      "version",
    ]);
  });

  it.each([
    "javascript:alert(1)",
    "file:///etc/passwd",
    "https://user:secret@example.test/login",
    "https://example.test/login#token",
    "example.test/login",
  ])("rejects unsafe link capture %s", (value) => {
    expect(() => captureEnvelopeSchema.parse({ ...baseCapture, kind: "link", value })).toThrow();
  });

  it("accepts an explicit HTTP(S) link without adding page metadata", () => {
    expect(
      captureEnvelopeSchema.parse({
        ...baseCapture,
        kind: "link",
        value: "https://example.test/path?case=1",
      }),
    ).toMatchObject({ kind: "link", value: "https://example.test/path?case=1" });
  });

  it("rejects page metadata", () => {
    expect(() =>
      captureEnvelopeSchema.parse({
        ...baseCapture,
        kind: "selection",
        value: "valid input",
        pageUrl: "https://private.example/account",
      }),
    ).toThrow();
  });

  it("rejects oversized input", () => {
    expect(() =>
      captureEnvelopeSchema.parse({
        ...baseCapture,
        kind: "selection",
        value: "x".repeat(5_001),
      }),
    ).toThrow();
  });
});

describe("internal messages", () => {
  it("requires both request-scoped consent fields", () => {
    expect(() =>
      internalMessageSchema.parse({
        type: "analysis.create",
        captureId: baseCapture.captureId,
        consent: { external_url_lookup: false },
      }),
    ).toThrow();
  });

  it("rejects unknown privileged messages", () => {
    expect(() => internalMessageSchema.parse({ type: "token.read" })).toThrow();
  });
});
