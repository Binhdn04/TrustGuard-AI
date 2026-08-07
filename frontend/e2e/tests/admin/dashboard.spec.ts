import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test.describe("Admin Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login and click mock admin login
    await page.goto("/login");
    await page.getByRole("button", { name: /Quyền Admin/i }).click();
    await page.waitForURL("**/");
    await page.goto("/admin");
    await expect(page).toHaveURL("/admin");
  });

  test("should display admin dashboard and pass accessibility checks", async ({ page }) => {
    // Wait for the admin content to load
    await expect(page.getByRole("heading", { name: /Admin Workspace/i })).toBeVisible();

    // Check tabs visibility
    await expect(page.getByRole("button", { name: /Fact-check Review/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /URL Security/i })).toBeVisible();

    // Accessibility check
    const accessibilityScanResults = await new AxeBuilder({ page })
      .disableRules(['color-contrast', 'heading-order'])
      .analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
  });
});
