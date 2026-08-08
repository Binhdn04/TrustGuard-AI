import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { installAdminReviewFlow } from "../../fixtures/analysis-mocks";

test("critical case → admin approval → blacklist entry", async ({ page }) => {
  await installAdminReviewFlow(page);
  await page.goto("/login");
  await page.getByRole("button", { name: /Quyền Admin/i }).click();
  await page.waitForURL("**/");
  await page.goto("/admin");

  await page.getByRole("tab", { name: "URL Security" }).click();
  await expect(page.getByText("tapdoanx-qua.example", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Blacklist" }).click();
  await page.getByLabel("Ghi chú reviewer").fill("Đã đối chiếu evidence snapshot và xác nhận domain giả mạo.");
  await page.getByRole("button", { name: "Xác nhận" }).click();
  await expect(page.getByText(/Không có URL đang chờ duyệt/i)).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});
