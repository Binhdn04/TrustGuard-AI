import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { DANGEROUS_URL, installUserAnalysisFlow } from "../../fixtures/analysis-mocks";

test("login → analyze → provisional → final → history", async ({ page }) => {
  await installUserAnalysisFlow(page);
  await page.goto("/login");
  await page.getByRole("button", { name: /Quyền User/i }).click();
  await page.waitForURL("**/");

  await page.getByRole("textbox").first().fill(`Nhận quà tại ${DANGEROUS_URL}`);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Phân tích" }).click();

  const provisionalBanner = page.getByRole("heading", { name: "Cảnh báo sơ bộ — chưa phải kết luận cuối" });
  await expect(provisionalBanner).toBeVisible();
  await expect(page.getByText(/Kế hoạch điều tra trực tiếp/i)).toBeVisible();
  await expect(page.getByText(/Sai Sự Thật/i)).toBeVisible({ timeout: 10_000 });
  await expect(provisionalBanner).toHaveCount(0);
  await expect(page.locator("a", { hasText: DANGEROUS_URL })).toHaveCount(0);

  await page.goto("/history");
  await expect(page.getByRole("heading", { name: /Lịch sử kiểm chứng/i })).toBeVisible();
  await expect(page.getByText(/Thông báo nhận quà/i)).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});
