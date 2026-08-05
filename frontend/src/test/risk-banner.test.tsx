import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { EvidenceList } from "@/components/analysis/evidence-list";
import { RiskBanner } from "@/components/analysis/risk-banner";

describe("risk result presentation", () => {
  it("uses an explicit critical warning", () => {
    render(
      <RiskBanner
        confidence={0.94}
        level="critical"
        score={92}
        summary="Liên kết có nhiều tín hiệu mạo danh."
        verdict="malicious"
      />,
    );

    expect(screen.getByText("Rủi ro nghiêm trọng")).toBeInTheDocument();
    expect(screen.getByText("Có dấu hiệu độc hại")).toBeInTheDocument();
    expect(screen.getByText("92")).toBeInTheDocument();
  });

  it("renders evidence URLs as non-clickable text", () => {
    render(
      <EvidenceList
        items={[
          {
            type: "domain_reputation",
            source: "test-provider",
            title: "Domain đáng ngờ",
            url: "https://suspicious.example/login",
            finding: "Domain mới và yêu cầu đăng nhập.",
            observed_at: "2026-08-03T13:00:00Z",
          },
        ]}
      />,
    );

    expect(screen.getByText("https://suspicious.example/login")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
