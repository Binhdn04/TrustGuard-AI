import { describe, expect, it } from "vitest";

import { decisionLabel, lifecycleLabel, securityLabel, statusLabel } from "@/lib/presentation/security-labels";

describe("nhãn trình bày tiếng Việt", () => {
  it("dịch enum API và hành động audit mà không đổi payload", () => {
    expect(statusLabel("pending_review")).toBe("Chờ duyệt");
    expect(lifecycleLabel("disabled")).toBe("Đã vô hiệu hóa");
    expect(decisionLabel("confirm_malicious")).toBe("Xác nhận độc hại");
    expect(securityLabel("add_to_blacklist")).toBe("Thêm vào danh sách chặn");
    expect(securityLabel("report_remediation_failed")).toBe("Khắc phục thất bại");
  });
});
