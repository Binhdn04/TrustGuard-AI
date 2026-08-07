import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mockAnalysisQueued, mockAnalysisEvents, mockAnalysisCompleted } from "../../fixtures/analysis-mocks";

test.describe("Analysis Workspace", () => {
  test("should complete a full analysis flow successfully", async ({ page }) => {
    // Setup mocks
    await mockAnalysisQueued(page);
    await mockAnalysisEvents(page, [
      {
        event_id: "evt-1",
        analysis_id: "test-analysis-123",
        sequence: 1,
        event_type: "analysis_status",
        occurred_at: new Date().toISOString(),
        payload: { status: "running" }
      },
      {
        event_id: "evt-2",
        analysis_id: "test-analysis-123",
        sequence: 2,
        event_type: "final_result",
        occurred_at: new Date().toISOString(),
        payload: { result_ref: "ref-1", status: "completed" }
      }
    ]);
    await mockAnalysisCompleted(page, { verdict: "safe", risk_level: "low" });

    // Navigate to homepage
    await page.goto("/");

    // Enter text and submit
    const textarea = page.getByPlaceholder(/Uống nước chanh/i);
    await textarea.click();
    await page.keyboard.type("Hello world this is a test");
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeEnabled();
    await submitBtn.click({ force: true });

    // Verify final results display

    // Verify final results display
    await expect(page.getByText(/Chưa Đủ Cơ Sở Kết Luận|Được Xác Nhận/i)).toBeVisible({ timeout: 15000 });
    
    // Accessibility check
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
  });
});
