import { describe, expect, it } from "vitest";

import { mapAnalysisResponseToViewModel } from "@/lib/mappers/analysis-v3-mapper";
import type { AnalysisResponseV3 } from "@/types/generated/api-v3";

function completedResponse(): AnalysisResponseV3 {
  return {
    contract_version: "v3",
    analysis_id: "analysis-1",
    status: "completed",
    input_type: "text",
    normalized_urls: [],
    claims: ["COVID vaccines contain microchips"],
    investigation_plan: [],
    risk_score: 20,
    risk_level: "low",
    verdict: "inconclusive",
    recommended_action: "show_caution",
    confidence: 0.9,
    summary: "A reviewed source refutes the claim.",
    reasons: ["The source rated the claim false."],
    evidence: [
      {
        type: "fact_check",
        source: "FactCheck.org",
        title: "Review",
        url: "https://www.factcheck.org/review/1",
        finding: "Neutral wording without a rating keyword",
        stance: "refutes",
        observed_at: "2026-08-12T00:00:00Z",
      },
    ],
    limitations: [],
    case_status: "not_required",
    scoring_version: "test-v1",
    created_at: "2026-08-12T00:00:00Z",
    completed_at: "2026-08-12T00:00:01Z",
  };
}

describe("analysis v3 mapper", () => {
  it("uses the backend fact-check stance instead of guessing from finding text", () => {
    const view = mapAnalysisResponseToViewModel(completedResponse(), {
      originalContent: "COVID vaccines contain microchips",
      consentToScanUrls: false,
    });

    expect(view.factCheck?.overallStance).toBe("refutes");
    expect(view.factCheck?.claims[0].stance).toBe("refutes");
  });
});
