import { Page } from "@playwright/test";
import { AnalysisResponseV3, AnalysisEventPageV3, AnalysisAcceptedResponseV3 } from "../../src/types/generated/api-v3";

export async function mockAnalysisQueued(page: Page) {
  await page.route("**/api/v3/analyses", async (route) => {
    const accepted: AnalysisAcceptedResponseV3 = {
      contract_version: "v3",
      analysis_id: "test-analysis-123",
      status: "queued",
      created_at: new Date().toISOString(),
    };
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify(accepted),
    });
  });
}

export async function mockAnalysisEvents(page: Page, events: any[]) {
  await page.route("**/api/v3/analyses/*/events*", async (route) => {
    const pageData: AnalysisEventPageV3 = {
      contract_version: "v3",
      events: events,
      next_cursor: null,
    };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(pageData),
    });
  });
}

export async function mockAnalysisCompleted(page: Page, overrides: Partial<AnalysisResponseV3> = {}) {
  await page.route("**/api/v3/analyses/*", async (route) => {
    // If the request is for events, ignore this route (handled by mockAnalysisEvents)
    if (route.request().url().includes("/events")) {
      return route.fallback();
    }

    const response: AnalysisResponseV3 = {
      contract_version: "v3",
      analysis_id: "test-analysis-123",
      status: "completed",
      input_type: "text",
      normalized_urls: [],
      claims: ["Test claim"],
      investigation_plan: [],
      risk_score: 50,
      risk_level: "medium",
      verdict: "inconclusive",
      recommended_action: "show_caution",
      confidence: 0.8,
      summary: "This is a mock summary from E2E fixture.",
      reasons: ["Mock reason"],
      evidence: [],
      limitations: [],
      case_status: "not_required",
      scoring_version: "v1",
      created_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      ...overrides
    };
    
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(response),
    });
  });
}
