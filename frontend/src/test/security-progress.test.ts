import { describe, expect, it } from "vitest";

import {
  SECURITY_PROGRESS_STAGES,
  isSecurityProgressStage,
  securityProgressLabel,
} from "@/lib/security-progress";

describe("security progress registry", () => {
  it("uses only coarse, allowlisted stages", () => {
    expect(SECURITY_PROGRESS_STAGES).toEqual([
      "running",
      "understanding",
      "scope_gate",
      "incident_response",
      "investigation",
      "official_link_verification",
      "security_memory_lookup",
      "risk_assessment",
      "assistant_response",
    ]);
    expect(isSecurityProgressStage("url_reputation")).toBe(false);
  });

  it("never renders a backend message or sensitive detail", () => {
    expect(securityProgressLabel("investigation", "started")).toBe("Đang kiểm tra các tín hiệu liên quan");
    expect(securityProgressLabel("url_reputation", "completed")).toBe("Đang tiếp tục kiểm tra nội dung");
    expect(securityProgressLabel("investigation", "unexpected-state")).toBe("Đang tiếp tục kiểm tra nội dung");
  });
});
