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
  await page.getByRole("button", { name: /Quyền quản trị bảo mật/i }).focus();
  await page.keyboard.press("Enter");
  await page.waitForURL("**/");
  await page.goto("/admin");
  await page.waitForURL("**/admin/review");

  await page.getByRole("button", { name: /Kết luận cần human review/i }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Credential path observed.")).toBeVisible();
  await page.getByLabel("Ghi chú của người duyệt").fill("Đã đối chiếu structured context và evidence snapshot.");
  await page.getByRole("button", { name: "Xác nhận quyết định" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("0 hồ sơ")).toBeVisible();
  await expectNoSeriousAccessibilityViolations(page, "[aria-labelledby='case-review-heading']");

  await page.goto("/admin/trust");
  await expect(page.getByRole("heading", { name: "Danh sách tin cậy & chặn" })).toBeVisible();

});
