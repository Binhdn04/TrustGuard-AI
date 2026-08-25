import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { OfficialVerificationPanel } from "@/components/analysis/official-verification-panel";
import { mapSecurityCaseViewModel } from "@/lib/mappers/security-case-view-model";
import { completedSecurityCase } from "@/test/fixtures/security-case-v4";
import type { OfficialLinkVerificationReportV4, VerificationStatusV4 } from "@/types/generated/api-v4";

const suspiciousUrl = "https://login-acme.example/collect?token=secret";
const officialUrl = "https://www.acme.example/careers/apply";

function report(status: VerificationStatusV4): OfficialLinkVerificationReportV4 {
  return {
    schema_version: "official-link-verification-v1",
    intent: { schema_version: "verification-intent-v1", organization_name: "ACME", derived_organization_names: [], claim_summary: "ACME dang tuyen dung", topic: "recruitment", requested_action: "register_or_apply", action_url_indices: [0] },
    publisher_verification: {
      applicable: true, status, reason_code: "publisher_registry_match", evidence_refs: ["source:aaaaaaaaaaaaaaaa"],
      identity: { identity_id: "10000000-0000-4000-8000-000000000001", identity_type: "primary_website", canonical_value: "acme.example", display_value: "acme.example", entity_name: "ACME", relationship: "primary_website", reviewed: true },
    },
    claim_verification: { applicable: true, status, reason_code: "claim_found", evidence_refs: ["source:aaaaaaaaaaaaaaaa"], topic: "recruitment" },
    resource_verification: {
      applicable: true, status, reason_code: "resource_compared", evidence_refs: ["link:bbbbbbbbbbbbbbbb"],
      match: {
        status: status === "VERIFIED" ? "EXACT_CANONICAL_URL" : "DIFFERENT_RESOURCE", reason_code: "canonical_comparison",
        user_resource: { schema_version: "resource-identity-v1", resource_type: "url", provider: null, resource_id: null, canonical_url: suspiciousUrl, match_key: suspiciousUrl },
        official_resource: { schema_version: "resource-identity-v1", resource_type: "url", provider: null, resource_id: null, canonical_url: officialUrl, match_key: officialUrl },
      },
    },
    overall_status: status, reason_code: `overall_${status.toLowerCase()}`,
    source_refs: [{ source_ref: "source:aaaaaaaaaaaaaaaa", identity: null, display_url: officialUrl, canonical_url: officialUrl, content_hash: null }],
    link_refs: [{ link_ref: "link:bbbbbbbbbbbbbbbb", source_ref: "source:aaaaaaaaaaaaaaaa", role: "application", display_url: suspiciousUrl, canonical_url: suspiciousUrl, resource: null }],
    limitations: ["search_provider_unavailable"], policy_version: "official-link-verification-v1",
  };
}

function viewModel(status: VerificationStatusV4) { return mapSecurityCaseViewModel(completedSecurityCase({ official_verification: report(status) })); }

describe("CP9 official link verification presentation", () => {
  it.each([
    ["VERIFIED", "Đã xác minh"], ["PARTIALLY_VERIFIED", "Xác minh một phần"],
    ["UNVERIFIED", "Chưa xác minh quan hệ chính thức"], ["CONFLICTING", "Thông tin mâu thuẫn"],
  ] as const)("renders %s in simple view with API actions", (status, label) => {
    render(<OfficialVerificationPanel viewModel={viewModel(status)} mode="simple" />);
    expect(screen.getAllByText(label)).toHaveLength(1);
    expect(screen.getByRole("heading", { name: "Xác minh quan hệ chính thức" })).toBeInTheDocument();
    expect(screen.queryByText(/overall_/)).not.toBeInTheDocument();
    expect(screen.getByText("Bước an toàn tiếp theo")).toBeInTheDocument();
  });

  it("shows analyst evidence and canonical chain without clickable URLs", () => {
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
    const { container } = render(<OfficialVerificationPanel viewModel={viewModel("CONFLICTING")} mode="analyst" />);
    expect(screen.getByText("Xác minh đơn vị phát hành")).toBeInTheDocument();
    expect(screen.getByText("Chuỗi tài nguyên / URL chuẩn hóa (chỉ văn bản)")).toBeInTheDocument();
    expect(screen.getByText(/search_provider_unavailable/)).toBeInTheDocument();
    expect(container.querySelectorAll("a")).toHaveLength(0);
    expect(screen.getAllByText(suspiciousUrl).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Sao chép URL đã gửi" }));
    expect(clipboard.writeText).toHaveBeenCalledWith(suspiciousUrl);
  });

  it("labels non-applicable components and does not invent a status", () => {
    const value = report("UNVERIFIED");
    value.claim_verification = { applicable: false, status: null, reason_code: "claim_not_present", evidence_refs: [], topic: null };
    render(<OfficialVerificationPanel viewModel={mapSecurityCaseViewModel(completedSecurityCase({ official_verification: value }))} mode="analyst" />);
    expect(screen.getByText("Xác minh nội dung").parentElement).toHaveTextContent("Không áp dụng");
  });

  it("shows automatically verified associations as exact-resource scoped", () => {
    const value = report("PARTIALLY_VERIFIED");
    value.identity_associations = [{
      association_id: "20000000-0000-4000-8000-000000000001",
      entity_name: "Tsinghua University",
      canonical_url: "https://v.wjx.cn/vm/to3MR3b.aspx",
      canonical_domain: "v.wjx.cn",
      relationship: "endorsed_third_party_service",
      assurance: "verified",
      confidence: 0.85,
      evidence_refs: ["identity-evidence:cccccccccccccccc"],
      discovered_at: "2026-08-21T00:00:00Z",
      verified_at: "2026-08-21T00:00:00Z",
      expires_at: "2026-08-28T00:00:00Z",
      policy_version: "identity-discovery-v2",
    }];

    render(<OfficialVerificationPanel viewModel={mapSecurityCaseViewModel(completedSecurityCase({ official_verification: value }))} mode="analyst" />);

    expect(screen.getByText("Liên kết danh tính theo tài nguyên")).toBeInTheDocument();
    expect(screen.getByText(/Đã tự động xác nhận chuỗi chứng thực/i)).toBeInTheDocument();
    expect(screen.getByText(/không xác nhận toàn bộ domain/i)).toBeInTheDocument();
    expect(screen.getByText("Đã xác minh")).toBeInTheDocument();
  });

  it("shows ownership, sender, and action as independent verification layers", () => {
    const value = report("PARTIALLY_VERIFIED");
    value.schema_version = "official-link-verification-v3";
    value.policy_version = "official-link-verification-v3";
    value.domain_ownership_verification = {
      applicable: true, status: "VERIFIED", reason_code: "independent_domain_ownership_verified", evidence_refs: [],
    };
    value.sender_verification = {
      applicable: true, status: "UNVERIFIED", reason_code: "message_sender_not_authenticated", evidence_refs: [],
    };
    value.action_endorsement_verification = {
      applicable: true, status: "UNVERIFIED", reason_code: "official_action_not_confirmed", evidence_refs: [],
    };

    render(<OfficialVerificationPanel viewModel={mapSecurityCaseViewModel(completedSecurityCase({ official_verification: value }))} mode="simple" />);

    expect(screen.getByText("Quyền sở hữu domain")).toBeInTheDocument();
    expect(screen.getByText("Danh tính người gửi")).toBeInTheDocument();
    expect(screen.getByText("Xác nhận hành động")).toBeInTheDocument();
    expect(screen.getByText(/Không nhập mật khẩu hay OTP/i)).toBeInTheDocument();
  });
});
