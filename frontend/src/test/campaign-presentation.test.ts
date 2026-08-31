import { describe, expect, it } from "vitest";

import {
  parseCampaignSignal,
  presentCampaign,
} from "@/lib/presentation/campaign-presentation";
import type { SecurityCampaignRecordV4 } from "@/types/generated/api-v4";

function campaign(aggregateSignals: Record<string, number>): SecurityCampaignRecordV4 {
  return {
    contract_version: "v4",
    campaign_id: "40000000-0000-4000-8000-000000000004",
    hypothesis: "Potential coordinated security campaign",
    analysis_ids: ["a-1", "a-2", "a-3", "a-4"],
    window_started_at: "2026-08-13T08:00:00Z",
    window_ended_at: "2026-08-13T10:30:00Z",
    aggregate_signals: aggregateSignals,
    reviewer_status: "pending_review",
    clustering_version: "security-clustering-v1",
    evidence_refs: ["evidence:campaign"],
    reviewer_id: null,
    review_note: null,
    reviewed_at: null,
    created_at: "2026-08-13T10:30:00Z",
  };
}

describe("campaign presentation", () => {
  it("covers all current signal prefixes and keeps values after the first colon intact", () => {
    const result = presentCampaign(campaign({
      "threat:BRAND_IMPERSONATION": 4,
      "scenario:recruitment": 4,
      "action:login": 4,
      "brand:acme bank": 4,
      "domain:login-acme.example": 3,
      "redirect:landing.example": 3,
      "pattern:otp_request": 2,
      "lexical:path_depth:2": 2,
      "future_signal:opaque:value": 2,
    }));

    expect(result.title).toBe("Nghi vấn mạo danh thương hiệu");
    expect(result.subtitle).toBe("Liên quan đến acme bank");
    expect(result.summary[0]).toBe("Cụm gồm 4 phân tích trong khoảng 2 giờ 30 phút.");
    expect(result.groups.primary.map((signal) => signal.prefix)).toEqual([
      "threat", "scenario", "action", "brand",
    ]);
    expect(result.groups.destination.map((signal) => signal.prefix)).toEqual(["domain", "redirect"]);
    expect(result.groups.supporting[0].label).toBe("Yêu cầu mã OTP");
    expect(result.groups.technical[0]).toMatchObject({
      prefix: "lexical",
      value: "path_depth:2",
      label: "Độ sâu đường dẫn: 2",
    });
    expect(result.groups.other[0]).toMatchObject({
      prefix: "future_signal",
      value: "opaque:value",
    });
  });

  it("uses a cautious fallback when only unknown or technical signals exist", () => {
    const result = presentCampaign(campaign({
      "threat:UNDETERMINED_SECURITY_THREAT": 4,
      "scenario:unknown": 4,
      "lexical:host:hyphenated": 3,
    }));

    expect(result.title).toBe("Cụm tín hiệu bảo mật cần duyệt");
    expect(result.topSignals).toEqual([]);
    expect(result.summary.at(-1)).toMatch(/chỉ có dữ liệu kỹ thuật/i);
  });

  it("does not discard a signal without a recognized prefix", () => {
    expect(parseCampaignSignal("opaque_signal", 3)).toMatchObject({
      prefix: "unknown",
      value: "opaque_signal",
      label: "opaque signal",
      count: 3,
      group: "other",
    });
  });
});
