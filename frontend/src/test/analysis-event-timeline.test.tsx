import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AnalysisEventTimeline } from "@/components/analysis/analysis-event-timeline";

describe("AnalysisEventTimeline", () => {
  it("renders backend event steps in order", () => {
    render(
      <AnalysisEventTimeline
        events={[
          {
            analysis_id: "analysis-1",
            status: "queued",
            step: "queued",
            occurred_at: "2026-08-06T08:00:00Z",
          },
          {
            analysis_id: "analysis-1",
            status: "completed",
            step: "completed",
            occurred_at: "2026-08-06T08:00:02Z",
          },
        ]}
      />,
    );

    expect(screen.getByText("Yêu cầu đã vào hàng đợi")).toBeInTheDocument();
    expect(screen.getByText("Phân tích hoàn tất")).toBeInTheDocument();
  });
});
