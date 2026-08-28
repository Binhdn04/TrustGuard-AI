import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { DANGEROUS_URL, FOLLOW_UP_ANALYSIS_ID, installUserAnalysisFlow } from "../../fixtures/analysis-mocks";

async function expectNoSeriousAccessibilityViolations(page: Page, selector: string) {
  const result = await new AxeBuilder({ page })
    .include(selector)
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .disableRules(["color-contrast"])
    .analyze();
  expect(result.violations.filter((violation) => violation.impact === "serious" || violation.impact === "critical")).toEqual([]);
}

async function expectThemeContrast(page: Page) {
  const ratio = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    const parse = (value: string) => {
      const hex = value.trim().replace("#", "");
      return [0, 2, 4].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
    };
    const luminance = (rgb: number[]) => rgb
      .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4)
      .reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
    const foreground = luminance(parse(style.getPropertyValue("--primary")));
    const background = luminance(parse(style.getPropertyValue("--card")));
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  expect(ratio).toBeGreaterThanOrEqual(4.5);
}

test("mobile keyboard flow: analyze → report/appeal → history resume", async ({ page }) => {
  await installUserAnalysisFlow(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/login");
  await page.getByRole("button", { name: /Quyền người dùng/i }).focus();
  await page.keyboard.press("Enter");
  await page.waitForURL("**/");
  await expectThemeContrast(page);
  await expectNoSeriousAccessibilityViolations(page, "[aria-label='Tạo case mới']");

  await page.getByRole("textbox").first().fill(`Nhận quà và đăng nhập tại ${DANGEROUS_URL}`);
  await expect(page.getByText(/kiểm tra liên kết bằng dịch vụ bảo mật/i)).toBeVisible();
  await page.getByRole("button", { name: /Gửi để đánh giá/i }).focus();
  await page.keyboard.press("Enter");

  await expect(page.getByText(/tín hiệu rủi ro cao tạm thời/i)).toBeVisible();
  await page.getByRole("tab", { name: "Kết quả" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Độc hại" })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText(/Không mở liên kết/i).first()).toBeVisible();
  await expect(page.getByText(/tín hiệu rủi ro cao tạm thời/i)).toHaveCount(0);

  await expect(page.getByRole("heading", { name: "Ba lớp cần phân biệt" })).toBeVisible();
  await page.getByRole("button", { name: "Kỹ thuật" }).click();
  const verification = page.locator("[aria-labelledby='official-verification-heading']");
  await expect(verification.getByText("Chuỗi tài nguyên / URL chuẩn hóa (chỉ văn bản)")).toBeVisible();
  await expect(verification.getByText(/resource_conflicts_with_official_source/)).toBeVisible();
  await expect(verification.locator("a")).toHaveCount(0);
  await expect(verification.getByText(DANGEROUS_URL).first()).toBeVisible();
  await page.getByRole("button", { name: "Cơ bản" }).click();
  await expectNoSeriousAccessibilityViolations(page, "[aria-labelledby='risk-heading']");

  await page.getByRole("tab", { name: "Trò chuyện" }).click();
  await page.getByRole("textbox").fill("Cảm ơn bạn");
  await page.getByRole("button", { name: /Gửi để đánh giá/i }).click();
  await expect(page.getByText(/Bạn có thể tiếp tục trò chuyện/i)).toBeVisible();
  await page.getByRole("tab", { name: "Kết quả" }).click();

  await page.getByText("Xem kết quả chi tiết", { exact: true }).click();
  await page.getByText("Báo cáo hoặc yêu cầu xem xét", { exact: true }).click();
  await page.getByRole("button", { name: "Gửi báo cáo" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText(/Bạn đã gửi báo cáo/i)).toBeVisible();
  await page.getByRole("button", { name: /Yêu cầu xem xét lại quyết định/i }).focus();
  await page.keyboard.press("Enter");
  await page.getByLabel("Lý do khiếu nại").fill("Bằng chứng cần được human reviewer kiểm tra lại");
  await page.getByRole("button", { name: "Gửi khiếu nại" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText(/Đã tiếp nhận khiếu nại/i)).toBeVisible();

  await page.goto("/history");
  await expect(page.getByRole("heading", { name: "Lịch sử trò chuyện" })).toBeVisible();
  await expect(page.getByText("Chuong trinh nhan qua")).toBeVisible();
  await page.getByRole("link", { name: /Mở cuộc trò chuyện/i }).click();
  await expect(page.getByRole("heading", { name: "Chi tiết cuộc trò chuyện" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Ba lớp cần phân biệt" })).toBeVisible();
  await page.getByLabel("Tiếp tục lượt kiểm tra với thông tin mới").fill("Người gửi tiếp tục yêu cầu đăng nhập tài khoản");
  await page.getByRole("button", { name: "Gửi thông tin bổ sung cho lượt kiểm tra" }).focus();
  await page.keyboard.press("Enter");
  await page.waitForURL(`**/cases/${FOLLOW_UP_ANALYSIS_ID}`);
  await expect(page.getByRole("heading", { name: "Tiếp tục cuộc trò chuyện" })).toBeVisible();
});
