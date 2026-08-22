import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PageCapturePanel } from "@/components/analysis/page-capture-panel";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";

describe("PageCapturePanel", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("automatically captures in memory and keeps the zoom controls", async () => {
    const capturePage = vi.fn().mockResolvedValue(new Blob(["jpeg"], { type: "image/jpeg" }));
    const createObjectUrl = vi.fn().mockReturnValue("blob:page-capture");
    const revokeObjectUrl = vi.fn();
    const NativeURL = URL;
    class MockURL extends NativeURL {
      static createObjectURL = createObjectUrl;
      static revokeObjectURL = revokeObjectUrl;
    }
    vi.stubGlobal("URL", MockURL);
    const api = {
      capturePage,
      getCapabilities: vi.fn().mockResolvedValue({ security_page_capture: true }),
    } as unknown as SecurityAnalysisApi;

    const rendered = render(
      <PageCapturePanel analysisId="analysis-1" urls={["https://example.com/login"]} api={api} />,
    );

    await waitFor(() => expect(capturePage).toHaveBeenCalledWith("analysis-1", 0));
    expect(await screen.findByAltText("Ảnh chụp trang đích https://example.com/login")).toBeInTheDocument();
    expect(createObjectUrl).toHaveBeenCalledOnce();
    expect(screen.queryByRole("button", { name: "Chụp ảnh web" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Chụp lại" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Phóng to ảnh chụp trang web" }));
    expect(screen.getByRole("dialog", { name: "Ảnh chụp trang web phóng to" })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Ảnh chụp trang web phóng to" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Phóng to ảnh chụp trang web" }));
    fireEvent.click(screen.getByRole("button", { name: "Đóng ảnh phóng to" }));
    expect(screen.queryByRole("dialog", { name: "Ảnh chụp trang web phóng to" })).not.toBeInTheDocument();

    rendered.unmount();
    expect(revokeObjectUrl).toHaveBeenCalledWith("blob:page-capture");
  });

  it("captures the newest URL and releases the previous image when a newer turn arrives", async () => {
    const capturePage = vi.fn().mockResolvedValue(new Blob(["jpeg"], { type: "image/jpeg" }));
    const createObjectUrl = vi.fn().mockReturnValueOnce("blob:first").mockReturnValueOnce("blob:second");
    const revokeObjectUrl = vi.fn();
    vi.stubGlobal("URL", class extends URL {
      static createObjectURL = createObjectUrl;
      static revokeObjectURL = revokeObjectUrl;
    });
    const api = {
      capturePage,
      getCapabilities: vi.fn().mockResolvedValue({ security_page_capture: true }),
    } as unknown as SecurityAnalysisApi;

    const rendered = render(
      <PageCapturePanel
        analysisId="analysis-1"
        urls={["https://example.com/one", "https://example.com/two"]}
        api={api}
      />,
    );

    await waitFor(() => expect(capturePage).toHaveBeenCalledWith("analysis-1", 1));
    expect(await screen.findByAltText("Ảnh chụp trang đích https://example.com/two")).toBeInTheDocument();
    expect(screen.queryByLabelText("Chọn liên kết")).not.toBeInTheDocument();

    rendered.rerender(
      <PageCapturePanel
        analysisId="analysis-2"
        urls={["https://example.com/one", "https://example.com/two", "https://example.com/three"]}
        api={api}
      />,
    );

    await waitFor(() => expect(revokeObjectUrl).toHaveBeenCalledWith("blob:first"));
    await waitFor(() => expect(capturePage).toHaveBeenCalledWith("analysis-2", 2));
    expect(await screen.findByAltText("Ảnh chụp trang đích https://example.com/three")).toBeInTheDocument();
    expect(capturePage).toHaveBeenCalledTimes(2);
  });
});
