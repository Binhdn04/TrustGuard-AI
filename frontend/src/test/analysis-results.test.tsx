import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { FactCheckSummary } from "@/components/analysis/fact-check-summary";
import { LinkSafetyPanel } from "@/components/analysis/link-safety-panel";
import type { FactCheckResult, LinkSafetyResult } from "@/types/analysis";

describe("Kết quả phân tích", () => {
  it("Fact-check là phần đầu tiên của kết quả và render multiple claims", () => {
    const mockFactCheck: FactCheckResult = {
      overallStance: "mixed",
      summary: "Mixed summary",
      confidence: 0.8,
      claims: [
        { id: "1", text: "Claim 1", stance: "supports", confidence: 0.9, explanation: "Exp 1", sources: [] },
        { id: "2", text: "Claim 2", stance: "refutes", confidence: 0.9, explanation: "Exp 2", sources: [] }
      ]
    };
    
    render(<FactCheckSummary result={mockFactCheck} />);
    
    // Check overall summary
    expect(screen.getByText("Mixed summary")).toBeInTheDocument();
    
    // Check multiple claims are rendered
    expect(screen.getByText(/"Claim 1"/)).toBeInTheDocument();
    expect(screen.getByText(/"Claim 2"/)).toBeInTheDocument();
  });

  it("unrated không hiển thị như claim đúng", () => {
    const mockFactCheck: FactCheckResult = {
      overallStance: "unrated",
      summary: "Unrated summary",
      confidence: null,
      claims: [
        { id: "1", text: "Alien claim", stance: "unrated", confidence: null, explanation: "No proof", sources: [] }
      ]
    };
    
    render(<FactCheckSummary result={mockFactCheck} />);
    
    // "Được nguồn xác nhận" should NOT be in the document
    expect(screen.queryByText(/Được nguồn xác nhận/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Chưa đủ bằng chứng/i)).toBeInTheDocument();
  });

  it("Không consent không hiển thị URL an toàn", () => {
    const mockLinkSafety: LinkSafetyResult = {
      status: "not_scanned",
      overallVerdict: null,
      urls: [],
      limitations: ["No consent"]
    };
    
    render(<LinkSafetyPanel result={mockLinkSafety} />);
    
    expect(screen.getByText(/Liên kết chưa được kiểm tra/i)).toBeInTheDocument();
    // Use a strict match to avoid matching the title "An toàn liên kết"
    expect(screen.queryByText(/^An toàn$/i)).not.toBeInTheDocument();
  });

  it("URL scan fail không làm mất fact-check result", () => {
    // This is essentially testing if they render independently without crashing
    const mockFactCheck: FactCheckResult = { overallStance: "supports", summary: "ok", confidence: 1, claims: [] };
    const mockLinkSafety: LinkSafetyResult = { status: "failed", overallVerdict: null, urls: [], limitations: ["Error"] };
    
    render(
      <div>
        <FactCheckSummary result={mockFactCheck} />
        <LinkSafetyPanel result={mockLinkSafety} />
      </div>
    );
    
    expect(screen.getByText("ok")).toBeInTheDocument(); // Fact-check still there
    expect(screen.getByText(/Không thể kiểm tra an toàn liên kết/i)).toBeInTheDocument(); // URL scan failed gracefully
  });
});
