import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ObservatoryWorkspace } from "@/components/admin/observatory/observatory-workspace";
import { composeRiskCounts } from "@/components/admin/observatory/risk-composition";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type {
  SecurityCampaignAuditRecordV4,
  SecurityCampaignRecordV4,
  SecurityDomainIntelligenceV4,
  SecurityThreatIntelligenceV4,
} from "@/types/generated/api-v4";

const auth = vi.hoisted(() => ({ role: "security_admin" as "security_admin" | "user", loading: false }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: auth.role },
    isLoading: auth.loading,
  }),
}));

const domain: SecurityDomainIntelligenceV4 = {
  domain: "gift-secure.example",
  analysis_count: 7,
  report_count: 2,
  risk_distribution: { MALICIOUS: 2, HIGH_RISK: 5 },
  threat_distribution: { PHISHING: 4, PROMOTION_PRIZE_SCAM: 3 },
  first_seen_at: "2026-08-10T08:00:00Z",
  last_seen_at: "2026-08-13T08:00:00Z",
  evidence_refs: ["evidence:domain"],
};

const threats: SecurityThreatIntelligenceV4[] = [
  {
    threat_type: "PHISHING", analysis_count: 3, report_count: 1,
    risk_distribution: { MALICIOUS: 2, HIGH_RISK: 1 }, domains: [domain.domain],
    first_seen_at: domain.first_seen_at, last_seen_at: domain.last_seen_at, evidence_refs: ["evidence:phishing"],
  },
  {
    threat_type: "PROMOTION_PRIZE_SCAM", analysis_count: 3, report_count: 1,
    risk_distribution: { HIGH_RISK: 3 }, domains: [domain.domain],
    first_seen_at: domain.first_seen_at, last_seen_at: domain.last_seen_at, evidence_refs: ["evidence:prize"],
  },
];

const campaign: SecurityCampaignRecordV4 = {
  contract_version: "v4",
  campaign_id: "50000000-0000-4000-8000-000000000005",
  hypothesis: "Shared prize lure and credential path",
  analysis_ids: ["a-1", "a-2", "a-3"],
  window_started_at: "2026-08-12T08:00:00Z",
  window_ended_at: "2026-08-13T08:00:00Z",
  aggregate_signals: { "domain:gift-secure.example": 3, "pattern:credential_path": 3 },
  reviewer_status: "confirmed",
  clustering_version: "security-clustering-v1",
  evidence_refs: ["evidence:campaign"],
  reviewer_id: "reviewer-1",
  review_note: "Signals verified",
  reviewed_at: "2026-08-13T09:00:00Z",
  created_at: "2026-08-13T08:10:00Z",
};

const campaignAudit: SecurityCampaignAuditRecordV4 = {
  audit_id: "60000000-0000-4000-8000-000000000006",
  campaign_id: campaign.campaign_id,
  previous_status: "pending_review",
  status: "confirmed",
  reviewer_id: "reviewer-1",
  note: "Signals verified",
  occurred_at: "2026-08-13T09:00:00Z",
  clustering_version: campaign.clustering_version,
  evidence_refs: campaign.evidence_refs,
};

function createApi(overrides: Partial<SecurityAnalysisApi> = {}): SecurityAnalysisApi {
  return {
    listDomainIntelligence: vi.fn().mockResolvedValue({ contract_version: "v4", items: [domain], total: 12, limit: 10, offset: 0 }),
    listThreatIntelligence: vi.fn().mockImplementation((query = {}) => Promise.resolve({ contract_version: "v4", items: threats, total: threats.length, limit: query.limit ?? 10, offset: query.offset ?? 0 })),
    pageSecurityMemory: vi.fn().mockResolvedValue({ contract_version: "v4", items: [], total: 18, limit: 1, offset: 0 }),
    pageSecurityCampaigns: vi.fn().mockResolvedValue({ contract_version: "v4", items: [campaign], total: 1, limit: 10, offset: 0 }),
    getSecurityCampaign: vi.fn().mockResolvedValue(campaign),
    listSecurityCampaignAudit: vi.fn().mockResolvedValue([campaignAudit]),
    ...overrides,
  } as unknown as SecurityAnalysisApi;
}

describe("FE6 Threat Observatory", () => {
  beforeEach(() => { auth.role = "security_admin"; auth.loading = false; });

  it("blocks non-admin users before any intelligence request", () => {
    auth.role = "user";
    const client = createApi();
    render(<ObservatoryWorkspace api={client} />);

    expect(screen.getByRole("heading", { name: "Cần quyền quản trị" })).toBeInTheDocument();
    expect(client.listDomainIntelligence).not.toHaveBeenCalled();
    expect(client.listThreatIntelligence).not.toHaveBeenCalled();
  });

  it("renders exact aggregate counts and composition without unsupported intelligence", async () => {
    const client = createApi();
    render(<ObservatoryWorkspace api={client} />);

    const domainElements = await screen.findAllByText(domain.domain);
    const domainRow = domainElements[0].closest("tr");
    expect(domainRow).not.toBeNull();
    expect(domainRow).toHaveTextContent("7 analyses");
    expect(domainRow).toHaveTextContent("MALICIOUS · 2");
    expect(domainRow).toHaveTextContent("PROMOTION_PRIZE_SCAM · 3");
    expect(screen.getByText(/33\.3%/)).toBeInTheDocument();
    expect(screen.getByText(/66\.7%/)).toBeInTheDocument();
    expect(screen.getByText("18")).toBeInTheDocument();
    expect(screen.queryByText(/geolocation|attack origin|active attack|trend arrow/i)).not.toBeInTheDocument();
    const composition = composeRiskCounts(threats);
    expect(composition.map(({ risk, count }) => ({ risk, count }))).toEqual([
      { risk: "MALICIOUS", count: 2 },
      { risk: "HIGH_RISK", count: 4 },
    ]);
    expect(composition[0].share).toBeCloseTo(100 / 3);
    expect(composition[1].share).toBeCloseTo(200 / 3);
  });

  it("sends explorer search/filter/page state to the aggregate APIs", async () => {
    const listDomainIntelligence = vi.fn().mockResolvedValue({ contract_version: "v4", items: [domain], total: 12, limit: 10, offset: 0 });
    const listThreatIntelligence = vi.fn().mockImplementation((query = {}) => Promise.resolve({ contract_version: "v4", items: threats, total: threats.length, limit: query.limit ?? 10, offset: query.offset ?? 0 }));
    const pageSecurityCampaigns = vi.fn().mockResolvedValue({ contract_version: "v4", items: [campaign], total: 1, limit: 10, offset: 0 });
    render(<ObservatoryWorkspace api={createApi({ listDomainIntelligence, listThreatIntelligence, pageSecurityCampaigns })} />);
    await screen.findAllByText(domain.domain);

    fireEvent.change(screen.getByLabelText("Tìm domain"), { target: { value: "gift-secure" } });
    fireEvent.change(screen.getByLabelText("Lọc domain theo risk"), { target: { value: "MALICIOUS" } });
    fireEvent.change(screen.getByLabelText("Lọc domain theo threat"), { target: { value: "PHISHING" } });
    const domainSection = screen.getByRole("heading", { name: "Domain quan sát" }).closest("section");
    expect(domainSection).not.toBeNull();
    fireEvent.click(within(domainSection as HTMLElement).getByRole("button", { name: "Tìm" }));

    await waitFor(() => expect(listDomainIntelligence).toHaveBeenLastCalledWith({ limit: 10, offset: 0, q: "gift-secure", risk: "MALICIOUS", threat_type: "PHISHING" }));
    fireEvent.click(screen.getByRole("button", { name: "Domain page sau" }));
    await waitFor(() => expect(listDomainIntelligence).toHaveBeenLastCalledWith({ limit: 10, offset: 10, q: "gift-secure", risk: "MALICIOUS", threat_type: "PHISHING" }));

    fireEvent.change(screen.getByLabelText("Lọc threat theo risk"), { target: { value: "HIGH_RISK" } });
    await waitFor(() => expect(listThreatIntelligence).toHaveBeenCalledWith({ limit: 10, offset: 0, risk: "HIGH_RISK" }));

    fireEvent.change(screen.getByLabelText("Tìm campaign hypothesis"), { target: { value: "prize lure" } });
    fireEvent.change(screen.getByLabelText("Lọc campaign status"), { target: { value: "confirmed" } });
    const campaignSection = screen.getByRole("heading", { name: "Chiến dịch" }).closest("section");
    expect(campaignSection).not.toBeNull();
    fireEvent.click(within(campaignSection as HTMLElement).getByRole("button", { name: "Tìm" }));
    await waitFor(() => expect(pageSecurityCampaigns).toHaveBeenLastCalledWith({ limit: 10, offset: 0, q: "prize lure", status: "confirmed" }));
  });

  it("loads campaign detail/audit and preserves hypothesis, members and named signals", async () => {
    const client = createApi();
    render(<ObservatoryWorkspace api={client} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(campaign.hypothesis) }));
    expect(await screen.findByText("domain:gift-secure.example")).toBeInTheDocument();
    expect(screen.getByText("Signals verified")).toBeInTheDocument();
    expect(screen.getByText("Phân tích liên quan").parentElement).toHaveTextContent("3");
    expect(client.getSecurityCampaign).toHaveBeenCalledWith(campaign.campaign_id);
    expect(client.listSecurityCampaignAudit).toHaveBeenCalledWith(campaign.campaign_id);
  });

  it("shows error retry and empty states from real responses", async () => {
    const listDomainIntelligence = vi.fn()
      .mockRejectedValueOnce(new Error("Domain aggregate unavailable"))
      .mockResolvedValueOnce({ contract_version: "v4", items: [], total: 0, limit: 10, offset: 0 });
    const pageSecurityCampaigns = vi.fn().mockResolvedValue({ contract_version: "v4", items: [], total: 0, limit: 10, offset: 0 });
    render(<ObservatoryWorkspace api={createApi({ listDomainIntelligence, pageSecurityCampaigns })} />);

    expect(await screen.findByRole("alert", { name: "" })).toHaveTextContent("Domain aggregate unavailable");
    fireEvent.click(screen.getAllByRole("button", { name: /Thử lại/i })[0]);
    expect(await screen.findByText("Không có domain phù hợp.")).toBeInTheDocument();
    expect(screen.getByText("Không có campaign phù hợp.")).toBeInTheDocument();
  });
});
