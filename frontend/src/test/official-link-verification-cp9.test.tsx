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
    ["VERIFIED", "Da xac minh"], ["PARTIALLY_VERIFIED", "Xac minh mot phan"],
    ["UNVERIFIED", "Chua xac minh"], ["CONFLICTING", "Thong tin mau thuan"],
  ] as const)("renders %s in simple view with API actions", (status, label) => {
    render(<OfficialVerificationPanel viewModel={viewModel(status)} mode="simple" />);
    expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    expect(screen.getByText("Buoc an toan tiep theo")).toBeInTheDocument();
  });

  it("shows analyst evidence and canonical chain without clickable URLs", () => {
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });
    const { container } = render(<OfficialVerificationPanel viewModel={viewModel("CONFLICTING")} mode="analyst" />);
    expect(screen.getByText("Publisher verification")).toBeInTheDocument();
    expect(screen.getByText("Resource / canonical chain (text only)")).toBeInTheDocument();
    expect(screen.getByText(/search_provider_unavailable/)).toBeInTheDocument();
    expect(container.querySelectorAll("a")).toHaveLength(0);
    expect(screen.getAllByText(suspiciousUrl).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Copy submitted URL" }));
    expect(clipboard.writeText).toHaveBeenCalledWith(suspiciousUrl);
  });

  it("labels non-applicable components and does not invent a status", () => {
    const value = report("UNVERIFIED");
    value.claim_verification = { applicable: false, status: null, reason_code: "claim_not_present", evidence_refs: [], topic: null };
    render(<OfficialVerificationPanel viewModel={mapSecurityCaseViewModel(completedSecurityCase({ official_verification: value }))} mode="analyst" />);
    expect(screen.getByText("Claim verification").parentElement).toHaveTextContent("Khong ap dung");
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

    expect(screen.getByText("Resource-scoped identity associations")).toBeInTheDocument();
    expect(screen.getByText(/Da tu dong xac nhan chuoi endorsement/i)).toBeInTheDocument();
    expect(screen.getByText(/khong xac nhan toan bo domain/i)).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
  });
});
