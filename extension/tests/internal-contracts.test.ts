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
  it("never accepts raw tokens in the Side Panel auth state", () => {
    expect(() => internalMessageSchema.parse({
      type: "auth.state",
      state: { status: "signed_in", accessToken: "must-stay-in-background" },
    })).toThrow();
  });

  it("requires both request-scoped consent fields", () => {
    expect(() =>
      internalMessageSchema.parse({
        type: "analysis.create",
        captureId: baseCapture.captureId,
        consent: { external_url_lookup: false },
      }),
    ).toThrow();
  });

  it("accepts only minimal analysis state and never raw content or tokens", () => {
    const state = {
      analysisId: baseCapture.captureId,
      executionMode: "async",
      status: "queued",
      cursor: null,
      lastSequence: 0,
      createdAt: baseCapture.createdAt,
      observedAt: baseCapture.createdAt,
    };
    expect(internalMessageSchema.parse({
      type: "analysis.submitted",
      analysis: state,
    })).toEqual({ type: "analysis.submitted", analysis: state });
    expect(() => internalMessageSchema.parse({
      type: "analysis.submitted",
      analysis: { ...state, message: "private capture" },
    })).toThrow();
    expect(() => internalMessageSchema.parse({
      type: "analysis.error",
      code: "offline",
      retryable: true,
      accessToken: "private token",
    })).toThrow();
  });

  it("allows only minimized Phase 6 progress messages", () => {
    const event = {
      eventId: baseCapture.captureId,
      analysisId: baseCapture.captureId,
      sequence: 1,
      status: "running",
      step: "understanding",
      kind: "progress",
      progressState: "started",
      occurredAt: baseCapture.createdAt,
    };
    expect(internalMessageSchema.parse({
      type: "analysis.events",
      analysisId: baseCapture.captureId,
      events: [event],
      nextCursor: "MQ",
    })).toEqual(expect.objectContaining({ events: [event] }));
    expect(() => internalMessageSchema.parse({
      type: "analysis.events",
      analysisId: baseCapture.captureId,
      events: [{ ...event, message: "private backend detail" }],
      nextCursor: "MQ",
    })).toThrow();
    expect(() => internalMessageSchema.parse({
      type: "analysis.wsTicket.issued",
      analysisId: baseCapture.captureId,
      url: `wss://api.example/api/v4/analyses/${baseCapture.captureId}/stream?ticket=one&access_token=secret`,
      expiresAt: baseCapture.createdAt,
    })).toThrow();
  });

  it("accepts only allow-listed public submission failures", () => {
    expect(internalMessageSchema.parse({
      type: "analysis.error",
      code: "rate_limited",
      retryable: true,
    })).toEqual({ type: "analysis.error", code: "rate_limited", retryable: true });
    expect(() => internalMessageSchema.parse({
      type: "analysis.error",
      code: "provider said private content",
      retryable: false,
    })).toThrow();
  });

  it("rejects unknown privileged messages", () => {
    expect(() => internalMessageSchema.parse({ type: "token.read" })).toThrow();
  });
});
