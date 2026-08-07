# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: tests\user\analysis-workspace.spec.ts >> Analysis Workspace >> should complete a full analysis flow successfully
- Location: e2e\tests\user\analysis-workspace.spec.ts:6:7

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: locator.click: Test timeout of 30000ms exceeded.
Call log:
  - waiting for locator('button[type="submit"]')

```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - button "Open Next.js Dev Tools" [ref=e7] [cursor=pointer]
  - alert [ref=e11]
  - generic [ref=e12]:
    - button "Toggle theme" [ref=e14]
    - generic [ref=e25]:
      - heading "AI PROTECT" [level=1] [ref=e30]
      - paragraph [ref=e31]: Giải pháp thông minh giúp phát hiện tin giả, lừa đảo (phishing) và các mối đe dọa trực tuyến theo thời gian thực.
    - generic [ref=e34]:
      - generic [ref=e35]:
        - heading "Chào mừng trở lại" [level=2] [ref=e36]
        - paragraph [ref=e37]: Đăng nhập vào hệ thống AI PROTECT
      - generic [ref=e38]:
        - generic [ref=e39]:
          - text: Email
          - textbox "name@example.com" [ref=e44]
        - generic [ref=e45]:
          - generic [ref=e46]:
            - generic [ref=e47]: Mật khẩu
            - link "Quên mật khẩu?" [ref=e48] [cursor=pointer]:
              - /url: "#"
          - textbox "••••••••" [ref=e53]
        - button "Đăng nhập" [ref=e54]
      - generic [ref=e57]: Demo MVP Login (Bỏ qua mật khẩu)
      - generic [ref=e62]:
        - button "Quyền User" [ref=e63]
        - button "Quyền Admin" [ref=e69]
      - paragraph [ref=e73]:
        - text: Chưa có tài khoản?
        - link "Đăng ký ngay" [ref=e74] [cursor=pointer]:
          - /url: /register
```

# Test source

```ts
  1  | import { test, expect } from "@playwright/test";
  2  | import AxeBuilder from "@axe-core/playwright";
  3  | import { mockAnalysisQueued, mockAnalysisEvents, mockAnalysisCompleted } from "../../fixtures/analysis-mocks";
  4  | 
  5  | test.describe("Analysis Workspace", () => {
  6  |   test("should complete a full analysis flow successfully", async ({ page }) => {
  7  |     // Setup mocks
  8  |     await mockAnalysisQueued(page);
  9  |     await mockAnalysisEvents(page, [
  10 |       {
  11 |         event_id: "evt-1",
  12 |         analysis_id: "test-analysis-123",
  13 |         sequence: 1,
  14 |         event_type: "analysis_status",
  15 |         occurred_at: new Date().toISOString(),
  16 |         payload: { status: "running" }
  17 |       },
  18 |       {
  19 |         event_id: "evt-2",
  20 |         analysis_id: "test-analysis-123",
  21 |         sequence: 2,
  22 |         event_type: "final_result",
  23 |         occurred_at: new Date().toISOString(),
  24 |         payload: { result_ref: "ref-1", status: "completed" }
  25 |       }
  26 |     ]);
  27 |     await mockAnalysisCompleted(page, { verdict: "safe", risk_level: "low" });
  28 | 
  29 |     // Navigate to homepage
  30 |     await page.goto("/");
  31 | 
  32 |     // Enter text and submit
  33 |     const textarea = page.getByPlaceholder(/Uống nước chanh/i);
  34 |     await textarea.click();
  35 |     await page.keyboard.type("Hello world this is a test");
  36 |     const submitBtn = page.locator('button[type="submit"]');
  37 |     await expect(submitBtn).toBeEnabled();
> 38 |     await submitBtn.click();
     |                     ^ Error: locator.click: Test timeout of 30000ms exceeded.
  39 | 
  40 |     // Verify final results display
  41 | 
  42 |     // Verify final results display
  43 |     await expect(page.getByText(/Chưa Đủ Cơ Sở Kết Luận|Được Xác Nhận/i)).toBeVisible({ timeout: 15000 });
  44 |     
  45 |     // Accessibility check
  46 |     const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
  47 |     expect(accessibilityScanResults.violations).toEqual([]);
  48 |   });
  49 | });
  50 | 
```