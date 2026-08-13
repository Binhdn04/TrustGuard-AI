import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { DANGEROUS_URL, installUserAnalysisFlow } from "../../fixtures/analysis-mocks";

test("login → analyze → provisional → final → history", async ({ page }) => {
  await installUserAnalysisFlow(page);
  await page.goto("/login");
  await page.getByRole("button", { name: /Quyền User/i }).click();
  await page.waitForURL("**/");

  await page.getByRole("textbox").first().fill(`Nhận quà và đăng nhập tại ${DANGEROUS_URL}`);
  await page.getByRole("checkbox", { name: /Cho phép kiểm tra URL/i }).check();
  await page.getByRole("button", { name: /Gửi để đánh giá/i }).click();

  await expect(page.getByText(/tín hiệu rủi ro cao tạm thời/i)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Nguy hiểm" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText(/Không mở liên kết/i)).toBeVisible();
  await expect(page.getByText(/tín hiệu rủi ro cao tạm thời/i)).toHaveCount(0);

  await page.goto("/history");
  await expect(page.getByRole("heading", { name: /Lịch sử Security Triage/i })).toBeVisible();
  await expect(page.getByText(/giả mạo chương trình trúng thưởng/i)).toBeVisible();

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
});
