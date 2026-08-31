import { describe, expect, it } from "vitest";

import {
  presentSignalNode,
  readableSignalValue,
  safeSignalDetail,
} from "@/lib/presentation/signal-map-presentation";

describe("signal map presentation", () => {
  it("translates composite signals without exposing enum names", () => {
    expect(readableSignalValue("unknown+UNDETERMINED_SECURITY_THREAT")).toBe(
      "Chưa xác định · Mối đe dọa chưa xác định",
    );
  });

  it("removes URL query and fragment from displayed node values", () => {
    expect(safeSignalDetail("https://example.test/login?token=private#step")).toBe(
      "https://example.test/login",
    );
  });

  it("presents technical tool names with reviewer-friendly labels", () => {
    expect(presentSignalNode({
      id: "step-1",
      kind: "step",
      label: "security_context_analysis",
      detail: "https://example.test/path?secret=value",
      sourceRef: "step-1",
    })).toEqual({
      label: "Phân tích ngữ cảnh",
      detail: "https://example.test/path",
    });
  });
});
