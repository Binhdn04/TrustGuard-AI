import { describe, expect, it } from "vitest";

import { isTrustedExtensionSender, isTrustedSidePanelSender } from "../src/runtime/sender";

const runtimeId = "abcdefghijklmnopabcdefghijklmnop";
const sidePanelUrl = `chrome-extension://${runtimeId}/sidepanel.html`;

describe("trusted internal sender boundary", () => {
  it("accepts only the exact Side Panel as a privileged request sender", () => {
    expect(isTrustedSidePanelSender({ id: runtimeId, url: sidePanelUrl }, runtimeId, sidePanelUrl)).toBe(true);
    expect(
      isTrustedSidePanelSender(
        { id: runtimeId, url: `chrome-extension://${runtimeId}/other.html` },
        runtimeId,
        sidePanelUrl,
      ),
    ).toBe(false);
    expect(isTrustedSidePanelSender({ id: "attacker", url: sidePanelUrl }, runtimeId, sidePanelUrl)).toBe(false);
  });

  it("rejects messages that do not originate from this extension", () => {
    expect(isTrustedExtensionSender({ id: runtimeId }, runtimeId)).toBe(true);
    expect(isTrustedExtensionSender({ id: "attacker" }, runtimeId)).toBe(false);
    expect(isTrustedExtensionSender({}, runtimeId)).toBe(false);
  });
});
