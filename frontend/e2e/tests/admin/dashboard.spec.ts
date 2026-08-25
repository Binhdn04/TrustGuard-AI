import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { installAdminReviewFlow } from "../../fixtures/analysis-mocks";

async function expectNoSeriousAccessibilityViolations(page: Page, selector: string) {
  const result = await new AxeBuilder({ page })
    .include(selector)
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .disableRules(["color-contrast"])
    .analyze();
  expect(result.violations.filter((violation) => violation.impact === "serious" || violation.impact === "critical")).toEqual([]);
}

test("admin keyboard review → Observatory → Trust → Unified Audit", async ({ page }) => {
  await installAdminReviewFlow(page);
  await page.goto("/login");
  await page.getByRole("button", { name: /Quyền Admin/i }).focus();
  await page.keyboard.press("Enter");
  await page.waitForURL("**/");
  await page.goto("/admin");
  await page.waitForURL("**/admin/review");

  await page.getByRole("button", { name: /Kết luận cần human review/i }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Credential path observed.")).toBeVisible();
  await page.getByLabel("Reviewer note").fill("Đã đối chiếu structured context và evidence snapshot.");
  await page.getByRole("button", { name: "Submit reviewed decision" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Terminal review")).toBeVisible();
  await expectNoSeriousAccessibilityViolations(page, "[aria-labelledby='case-review-heading']");

  await page.goto("/admin/observatory");
  await expect(page.getByRole("heading", { name: "Threat Observatory" })).toBeVisible();
  await expect(page.getByText("tapdoanx-qua.example", { exact: true }).first()).toBeVisible();
  await page.getByRole("button", { name: /Shared prize lure and credential path/i }).click();
  await expect(page.getByText("domain:tapdoanx-qua.example")).toBeVisible();

  await page.goto("/admin/trust");
  await expect(page.getByRole("heading", { name: "Trust Control Center" })).toBeVisible();
  await expect(page.getByText("Verified corporate registry")).toBeVisible();
  await page.getByRole("button", { name: "Create new version" }).click();
  await expect(page.getByText(/existing record is not edited/i)).toBeVisible();
  await page.getByLabel("Brand provenance").fill("Reviewed E2E identity version");
  await page.getByRole("button", { name: "Review new version" }).click();
  await page.getByRole("button", { name: "Confirm new version" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.goto("/admin/audit");
  await expect(page.getByRole("heading", { name: "Unified Audit", exact: true })).toBeVisible();
  await expect(page.getByText("brand_created")).toBeVisible();
  await expect(page.getByText("registry:tapdoanx")).toBeVisible();
});
