import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ConversationPanel } from "@/components/analysis/conversation-panel";
import type { SecurityProgressViewModel } from "@/lib/security-progress";

const progress: SecurityProgressViewModel = {
  latest: {
    eventId: "investigation-completed",
    analysisId: "analysis-1",
    sequence: 4,
    stage: "investigation",
    state: "completed",
    label: "Đã hoàn tất kiểm tra các tín hiệu liên quan",
  },
  timeline: [
    {
      eventId: "understanding-started",
      analysisId: "analysis-1",
      sequence: 2,
      stage: "understanding",
      state: "started",
      label: "Đang phân tích ngữ cảnh bảo mật",
    },
    {
      eventId: "investigation-completed",
      analysisId: "analysis-1",
      sequence: 4,
      stage: "investigation",
      state: "completed",
      label: "Đã hoàn tất kiểm tra các tín hiệu liên quan",
    },
  ],
};

function panel(
  mode: "simple" | "analyst",
  currentProgress = progress,
  state: "RUNNING" | "PROVISIONAL_WARNING" = "RUNNING",
) {
  return (
    <ConversationPanel
      turns={[]}
      state={state}
      transport="connected"
      error={null}
      recoveryAction={null}
      busy
      mode={mode}
      progress={currentProgress}
      onSubmit={() => undefined}
      onRetry={() => undefined}
      onRecover={() => undefined}
    />
  );
}

describe("controlled progress card", () => {
  it("passes only the latest allowlisted label into the simple busy bubble", () => {
    render(panel("simple"));

    expect(screen.getByRole("status")).toHaveTextContent("Đã hoàn tất kiểm tra các tín hiệu liên quan");
    expect(screen.queryByRole("list", { name: "Tiến trình kiểm tra" })).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    expect(document.querySelector("[class*='motion-reduce:animate-none']")).toBeInTheDocument();
  });

  it("shows an analyst-only coarse timeline without tool details", () => {
    render(panel("analyst"));

    const timeline = screen.getByRole("list", { name: "Tiến trình kiểm tra" });
    expect(within(timeline).getByText("Đang phân tích ngữ cảnh bảo mật")).toBeInTheDocument();
    expect(within(timeline).getByText("Đã hoàn tất kiểm tra các tín hiệu liên quan")).toBeInTheDocument();
    expect(timeline).toHaveAttribute("aria-live", "off");
    expect(screen.queryByText(/provider|DNS|redirect/i)).not.toBeInTheDocument();
  });

  it("keeps the generic busy label when there is no usable progress event", () => {
    render(panel("simple", { latest: null, timeline: [] }));

    expect(screen.getByRole("status")).toHaveTextContent("Trợ lý đang kiểm tra nội dung");
  });

  it("keeps the provisional warning explicitly temporary while progress is busy", () => {
    render(panel("simple", progress, "PROVISIONAL_WARNING"));

    expect(screen.getByText(/tạm thời từ API; đây chưa phải kết luận cuối/i)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Đã hoàn tất kiểm tra các tín hiệu liên quan");
  });
});
