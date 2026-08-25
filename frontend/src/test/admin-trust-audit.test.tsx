import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuditWorkspace } from "@/components/admin/audit/audit-workspace";
import { TrustWorkspace } from "@/components/admin/trust/trust-workspace";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type {
  BrandRecordV4,
  SecurityAdminAuditEventV4,
  SecurityCampaignAuditRecordV4,
  SecurityCampaignRecordV4,
  SecurityMemoryAuditRecordV4,
  SecurityMemoryRecordV4,
  WhitelistRecordV4,
} from "@/types/generated/api-v4";

const auth = vi.hoisted(() => ({ role: "security_admin" as "security_admin" | "user", loading: false }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: auth.role },
    isLoading: auth.loading,
  }),
}));

const brand: BrandRecordV4 = {
  brand_id: "10000000-0000-4000-8000-000000000001", name: "ACME Bank",
  aliases: ["ACME"], official_domains: ["acme.example"], official_contacts: ["1900-0000"],
  official_identities: [], supersedes: null,
  provenance: "Verified corporate registry", policy_version: "brand-registry-v1",
  effective_from: "2026-08-13T08:00:00Z", effective_until: null, lifecycle: "active",
  reviewer_id: "admin-1", created_at: "2026-08-13T08:00:00Z",
};

const whitelist: WhitelistRecordV4 = {
  whitelist_id: "20000000-0000-4000-8000-000000000002", indicator: "acme.example",
  scope: "domain", provenance: "Official security contact", policy_version: "whitelist-v1",
  effective_from: "2026-08-13T08:00:00Z", effective_until: null, lifecycle: "active",
  reviewer_id: "admin-1", created_at: "2026-08-13T08:00:00Z",
};

const memory: SecurityMemoryRecordV4 = {
  contract_version: "v4", memory_id: "30000000-0000-4000-8000-000000000003",
  analysis_id: "31000000-0000-4000-8000-000000000003", canonical_domains: ["fraud.example"],
  url_fingerprints: ["https://fraud.example/login"], redirect_targets: [], claimed_brand: "ACME Bank",
  scenario: "account_verification", requested_action: "login", security_patterns: ["credential_path"],
  lexical_features: [], threat_type: "PHISHING", risk: "HIGH_RISK",
  risk_policy_version: "security-risk-v1", fingerprint_version: "security-fingerprint-v1",
  first_seen_at: "2026-08-13T08:00:00Z", last_seen_at: "2026-08-13T09:00:00Z",
  report_count: 2, admin_verdict: "unreviewed", evidence_refs: ["evidence:memory"],
};

const memoryAudit: SecurityMemoryAuditRecordV4 = {
  audit_id: "32000000-0000-4000-8000-000000000003", memory_id: memory.memory_id,
  previous_verdict: "unreviewed", verdict: "malicious", reviewer_id: "admin-1",
  note: "Confirmed by evidence", occurred_at: "2026-08-13T09:10:00Z",
  risk_policy_version: memory.risk_policy_version, fingerprint_version: memory.fingerprint_version,
  evidence_refs: memory.evidence_refs,
};

const campaign: SecurityCampaignRecordV4 = {
  contract_version: "v4", campaign_id: "40000000-0000-4000-8000-000000000004",
  hypothesis: "Shared credential lure", analysis_ids: ["a-1", "a-2", "a-3"],
  window_started_at: "2026-08-12T08:00:00Z", window_ended_at: "2026-08-13T08:00:00Z",
  aggregate_signals: { "domain:fraud.example": 3, "pattern:credential_path": 3 },
  reviewer_status: "pending_review", clustering_version: "security-clustering-v1",
  evidence_refs: ["evidence:campaign"], reviewer_id: null, review_note: null, reviewed_at: null,
  created_at: "2026-08-13T08:00:00Z",
};

const campaignAudit: SecurityCampaignAuditRecordV4 = {
  audit_id: "41000000-0000-4000-8000-000000000004", campaign_id: campaign.campaign_id,
  previous_status: "pending_review", status: "confirmed", reviewer_id: "admin-1",
  note: "Signals verified", occurred_at: "2026-08-13T09:20:00Z",
  clustering_version: campaign.clustering_version, evidence_refs: campaign.evidence_refs,
};

const unifiedAudit: SecurityAdminAuditEventV4 = {
  audit_id: "50000000-0000-4000-8000-000000000005", resource_type: "campaign",
  resource_id: campaign.campaign_id, action: "campaign_confirmed", actor_id: "admin-1",
  note: "Signals verified", occurred_at: "2026-08-13T09:20:00Z", evidence_refs: ["evidence:campaign"],
};

function securityClient(overrides: Partial<SecurityAnalysisApi> = {}): SecurityAnalysisApi {
  return {
    pageBrands: vi.fn().mockResolvedValue({ contract_version: "v4", items: [brand], total: 1, limit: 10, offset: 0 }),
    createBrand: vi.fn().mockResolvedValue(brand),
    createBrandVersion: vi.fn().mockResolvedValue({ ...brand, supersedes: brand.brand_id }),
    disableBrand: vi.fn().mockResolvedValue({ ...brand, lifecycle: "disabled" }),
    pageWhitelist: vi.fn().mockResolvedValue({ contract_version: "v4", items: [whitelist], total: 1, limit: 10, offset: 0 }),
    createWhitelist: vi.fn().mockResolvedValue(whitelist),
    disableWhitelist: vi.fn().mockResolvedValue({ ...whitelist, lifecycle: "disabled" }),
    pageSecurityMemory: vi.fn().mockResolvedValue({ contract_version: "v4", items: [memory], total: 1, limit: 10, offset: 0 }),
    listSecurityMemoryAudit: vi.fn().mockResolvedValue([memoryAudit]),
    correctSecurityMemory: vi.fn().mockResolvedValue({ ...memory, admin_verdict: "malicious" }),
    pageSecurityCampaigns: vi.fn().mockResolvedValue({ contract_version: "v4", items: [campaign], total: 1, limit: 10, offset: 0 }),
    getSecurityCampaign: vi.fn().mockResolvedValue(campaign),
    listSecurityCampaignAudit: vi.fn().mockResolvedValue([campaignAudit]),
    reviewSecurityCampaign: vi.fn().mockResolvedValue({ ...campaign, reviewer_status: "confirmed", reviewer_id: "admin-1", review_note: "Signals verified", reviewed_at: "2026-08-13T09:20:00Z" }),
    listAdminAudit: vi.fn().mockResolvedValue({ contract_version: "v4", items: [unifiedAudit], total: 1, limit: 20, offset: 0 }),
    ...overrides,
  } as unknown as SecurityAnalysisApi;
}

describe("FE8 trust lifecycle and audit isolation", () => {
  beforeEach(() => { auth.role = "security_admin"; auth.loading = false; });

  it("blocks non-admin users before trust or audit API calls", () => {
    auth.role = "user";
    const api = securityClient();
    render(<TrustWorkspace api={api} />);
    expect(screen.getByRole("heading", { name: "Cần quyền quản trị" })).toBeInTheDocument();
    expect(api.pageBrands).not.toHaveBeenCalled();
    expect(api.listAdminAudit).not.toHaveBeenCalled();
  });

  it("creates and disables a brand only after explicit confirmation", async () => {
    const createBrand = vi.fn().mockResolvedValue(brand);
    const disableBrand = vi.fn().mockResolvedValue({ ...brand, lifecycle: "disabled" });
    const api = securityClient({ createBrand, disableBrand });
    render(<TrustWorkspace api={api} />);
    fireEvent.click(screen.getByText("Nguồn chính thức và công cụ nâng cao"));
    fireEvent.click(screen.getByRole("button", { name: "Nguồn chính thức" }));
    expect(await screen.findByText("ACME Bank")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Thêm thương hiệu" }));
    fireEvent.change(screen.getByLabelText("Tên thương hiệu"), { target: { value: "Example Bank" } });
    fireEvent.change(screen.getByLabelText("Domain chính thức"), { target: { value: "bank.example, secure.bank.example" } });
    fireEvent.change(screen.getByLabelText("Nguồn xác minh thương hiệu"), { target: { value: "Verified registry entry" } });
    fireEvent.change(screen.getByLabelText("Thời điểm thương hiệu bắt đầu hiệu lực"), { target: { value: "2026-08-14T08:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Xem lại yêu cầu tạo" }));
    expect(createBrand).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận tạo" }));
    await waitFor(() => expect(createBrand).toHaveBeenCalledWith(expect.objectContaining({
      name: "Example Bank", official_domains: ["bank.example", "secure.bank.example"],
      provenance: "Verified registry entry", effective_from: expect.stringContaining("2026-08-14"),
    })));

    fireEvent.click(screen.getByRole("button", { name: "Vô hiệu hóa" }));
    expect(disableBrand).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận vô hiệu hóa" }));
    await waitFor(() => expect(disableBrand).toHaveBeenCalledWith(brand.brand_id));
  });

  it("creates an immutable brand version through the supersede endpoint", async () => {
    const createBrandVersion = vi.fn().mockResolvedValue({ ...brand, brand_id: "new-version", supersedes: brand.brand_id });
    render(<TrustWorkspace api={securityClient({ createBrandVersion })} />);
    fireEvent.click(screen.getByText("Nguồn chính thức và công cụ nâng cao"));
    fireEvent.click(screen.getByRole("button", { name: "Nguồn chính thức" }));
    expect(await screen.findByText("ACME Bank")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Tạo phiên bản mới" }));
    expect(screen.getByText(/bản ghi hiện tại không bị chỉnh sửa/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Nguồn xác minh thương hiệu"), { target: { value: "Reviewed registry update" } });
    fireEvent.click(screen.getByRole("button", { name: "Xem lại phiên bản mới" }));
    expect(createBrandVersion).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận phiên bản mới" }));
    await waitFor(() => expect(createBrandVersion).toHaveBeenCalledWith(brand.brand_id, expect.objectContaining({
      name: brand.name, provenance: "Reviewed registry update", official_domains: brand.official_domains,
    })));
  });

  it("creates and disables whitelist entries with scope and lifecycle confirmation", async () => {
    const createWhitelist = vi.fn().mockResolvedValue(whitelist);
    const disableWhitelist = vi.fn().mockResolvedValue({ ...whitelist, lifecycle: "disabled" });
    render(<TrustWorkspace api={securityClient({ createWhitelist, disableWhitelist })} />);
    expect(await screen.findByText("acme.example")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Thêm ngoại lệ" }));
    fireEvent.change(screen.getByLabelText("Giá trị ngoại lệ tin cậy"), { target: { value: "safe.example" } });
    fireEvent.change(screen.getByLabelText("Phạm vi ngoại lệ tin cậy"), { target: { value: "domain" } });
    fireEvent.change(screen.getByLabelText("Provenance ngoại lệ tin cậy"), { target: { value: "Official security bulletin" } });
    fireEvent.change(screen.getByLabelText("Thời điểm bắt đầu hiệu lực"), { target: { value: "2026-08-14T08:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Xem lại yêu cầu tạo" }));
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận tạo" }));
    await waitFor(() => expect(createWhitelist).toHaveBeenCalledWith(expect.objectContaining({ indicator: "safe.example", scope: "domain", provenance: "Official security bulletin" })));
    fireEvent.click(screen.getByRole("button", { name: "Vô hiệu hóa" }));
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận vô hiệu hóa" }));
    await waitFor(() => expect(disableWhitelist).toHaveBeenCalledWith(whitelist.whitelist_id));
  });

  it("loads Memory evidence/audit and writes a noted v4 correction", async () => {
    const correctSecurityMemory = vi.fn().mockResolvedValue({ ...memory, admin_verdict: "malicious" });
    const api = securityClient({ correctSecurityMemory });
    render(<TrustWorkspace api={api} />);
    fireEvent.click(screen.getByText("Nguồn chính thức và công cụ nâng cao"));
    fireEvent.click(screen.getByRole("button", { name: "Security Memory" }));
    fireEvent.click(await screen.findByRole("button", { name: /ACME Bank/ }));
    expect(await screen.findByText("evidence:memory")).toBeInTheDocument();
    expect(screen.getByText(/Chưa duyệt → Độc hại/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Kết luận hiệu chỉnh"), { target: { value: "malicious" } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Confirmed by evidence" } });
    fireEvent.click(screen.getByRole("button", { name: "Lưu hiệu chỉnh" }));
    await waitFor(() => expect(correctSecurityMemory).toHaveBeenCalledWith(memory.memory_id, { verdict: "malicious", note: "Confirmed by evidence" }));
  });

  it("reviews a campaign from named signals and real detail/audit APIs", async () => {
    const reviewSecurityCampaign = vi.fn().mockResolvedValue({ ...campaign, reviewer_status: "confirmed", reviewer_id: "admin-1", review_note: "Signals verified", reviewed_at: "2026-08-13T09:20:00Z" });
    const api = securityClient({ reviewSecurityCampaign });
    render(<TrustWorkspace api={api} />);
    fireEvent.click(screen.getByText("Nguồn chính thức và công cụ nâng cao"));
    fireEvent.click(screen.getByRole("button", { name: "Chiến dịch" }));
    fireEvent.click(await screen.findByRole("button", { name: /Shared credential lure/ }));
    await waitFor(() => expect(api.getSecurityCampaign).toHaveBeenCalledWith(campaign.campaign_id));
    expect(api.listSecurityCampaignAudit).toHaveBeenCalledWith(campaign.campaign_id);
    expect(screen.getByText("Tín hiệu có tên").parentElement).toHaveTextContent("domain:fraud.example: 3");
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Signals verified" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi kết quả duyệt" }));
    await waitFor(() => expect(reviewSecurityCampaign).toHaveBeenCalledWith(campaign.campaign_id, { decision: "confirmed", note: "Signals verified" }));
  });

  it("renders only fields present in the unified v4 audit contract", async () => {
    const listAdminAudit = vi.fn().mockResolvedValue({ contract_version: "v4", items: [unifiedAudit], total: 1, limit: 20, offset: 0 });
    render(<AuditWorkspace api={securityClient({ listAdminAudit })} />);
    expect(await screen.findByText("Chiến dịch đã được xác nhận")).toBeInTheDocument();
    expect(screen.getByText("Signals verified")).toBeInTheDocument();
    expect(screen.getByText("evidence:campaign")).toBeInTheDocument();
    expect(screen.queryByText(/^before value$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^after value$/i)).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Lọc lịch sử theo loại tài nguyên"), { target: { value: "campaign" } });
    fireEvent.change(screen.getByLabelText("Lọc lịch sử theo hành động"), { target: { value: "campaign_confirmed" } });
    await waitFor(() => expect(listAdminAudit).toHaveBeenLastCalledWith({ limit: 20, offset: 0, resource_type: "campaign", action: "campaign_confirmed" }));
  });
});
