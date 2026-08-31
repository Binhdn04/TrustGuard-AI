import { describe, expect, it } from "vitest";

import { presentSecurityMemory } from "@/lib/presentation/security-memory-presentation";
import type { SecurityMemoryRecordV4 } from "@/types/generated/api-v4";

function memory(overrides: Partial<SecurityMemoryRecordV4> = {}): SecurityMemoryRecordV4 {
  return {
    contract_version: "v4",
    memory_id: "30000000-0000-4000-8000-000000000003",
    analysis_id: "31000000-0000-4000-8000-000000000003",
    canonical_domains: ["youtube.com"],
    url_fingerprints: [],
    redirect_targets: [],
    claimed_brand: null,
    scenario: "unknown",
    requested_action: null,
    security_patterns: [],
    lexical_features: [],
    threat_type: "UNDETERMINED_SECURITY_THREAT",
    risk: "INSUFFICIENT_EVIDENCE",
    risk_policy_version: "security-risk-v1",
    fingerprint_version: "security-fingerprint-v1",
    first_seen_at: "2026-08-13T08:00:00Z",
    last_seen_at: "2026-08-13T08:00:00Z",
    report_count: 0,
    admin_verdict: "unreviewed",
    evidence_refs: ["evidence:first", "evidence:second"],
    ...overrides,
  };
}

describe("security memory presentation", () => {
  it("turns the empty-state technical values into reviewer-friendly text", () => {
    const result = presentSecurityMemory(memory());

    expect(result.title).toBe("youtube.com");
    expect(result.threatLabel).toBe("Mối đe dọa chưa xác định");
    expect(result.reportLabel).toBe("Chưa có báo cáo liên kết");
    expect(result.evidenceLabel).toBe("2 bằng chứng");
    expect(result.summary).toContain("Chưa ghi nhận dấu hiệu bổ trợ.");
    expect(result.summary.join(" ")).not.toContain("UNDETERMINED_SECURITY_THREAT");
  });

  it("labels semantic context and supporting patterns without changing source values", () => {
    const result = presentSecurityMemory(memory({
      claimed_brand: "ACME Bank",
      scenario: "account_verification",
      requested_action: "share_otp",
      security_patterns: ["otp_request", "urgency"],
      threat_type: "CREDENTIAL_THEFT",
      risk: "HIGH_RISK",
      report_count: 3,
    }));

    expect(result.title).toBe("ACME Bank");
    expect(result.subtitle).toBe("Domain chính: youtube.com");
    expect(result.scenarioLabel).toBe("Xác minh tài khoản");
    expect(result.actionLabel).toBe("Chia sẻ mã OTP");
    expect(result.patternLabels).toEqual(["Yêu cầu mã OTP", "Tạo cảm giác khẩn cấp"]);
    expect(result.reportLabel).toBe("3 báo cáo liên kết");
  });
});
