import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CaseDetail } from "@/components/cases/case-detail";
import { CaseLibrary } from "@/components/cases/case-library";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { ApiError } from "@/lib/api/http-analysis-api";
import {
  parseSecurityHistoryQuery,
  securityHistoryHref,
  toSecurityAnalysisPageQuery,
} from "@/lib/mappers/security-history-query";
import { completedSecurityCase } from "@/test/fixtures/security-case-v4";
import type { SecurityConversationV4, SecurityScopeResponseV4 } from "@/types/generated/api-v4";

const replace = vi.fn();

vi.mock("next/navigation", () => ({
  usePathname: () => "/history",
  useRouter: () => ({ replace }),
}));

function conversation(version = 3): SecurityConversationV4 {
  const analysis = completedSecurityCase();
  return {
    contract_version: "v4",
    conversation_id: analysis.conversation_id,
    status: "active",
    active_analysis_id: analysis.analysis_id,
    context_version: version,
    summary: {
      security_context: analysis.security_context,
      evidence_refs: ["evidence:aaaaaaaaaaaaaaaa"],
    },
    created_at: "2026-08-13T08:00:00Z",
    updated_at: "2026-08-13T08:02:00Z",
    expires_at: "2026-09-12T08:00:00Z",
  };
}

function api(overrides: Partial<SecurityAnalysisApi>): SecurityAnalysisApi {
  return {
    getCapabilities: vi.fn(), createAnalysis: vi.fn(), getAnalysis: vi.fn(), getAdminAnalysis: vi.fn(), listAnalyses: vi.fn(),
    pageAnalyses: vi.fn(), getConversation: vi.fn(), listConversations: vi.fn(), getAnalysisEvents: vi.fn(),
    createWebSocketTicket: vi.fn(), reportAnalysis: vi.fn(), listReports: vi.fn().mockResolvedValue([]),
    createAppeal: vi.fn(), listAnalysisAppeals: vi.fn().mockResolvedValue([]), listAdminReports: vi.fn(),
    decideAdminReport: vi.fn(), listAdminAppeals: vi.fn(), decideAdminAppeal: vi.fn(), createBrand: vi.fn(),
    listBrands: vi.fn(), pageBrands: vi.fn(), disableBrand: vi.fn(), createWhitelist: vi.fn(),
    listWhitelist: vi.fn(), pageWhitelist: vi.fn(), disableWhitelist: vi.fn(), listSecurityMemory: vi.fn(),
    pageSecurityMemory: vi.fn(), correctSecurityMemory: vi.fn(), listSecurityMemoryAudit: vi.fn(),
    listSecurityCampaigns: vi.fn(), pageSecurityCampaigns: vi.fn(), getSecurityCampaign: vi.fn(),
    reviewSecurityCampaign: vi.fn(), listSecurityCampaignAudit: vi.fn(), listDomainIntelligence: vi.fn(),
    listThreatIntelligence: vi.fn(), listAdminAudit: vi.fn(), ...overrides,
  };
}

function page(items: SecurityScopeResponseV4[], total = items.length, offset = 0) {
  return { contract_version: "v4" as const, items, total, limit: 10, offset };
}

describe("FE5 security history query", () => {
  it("normalizes URL state into the supported server query", () => {
    const query = parseSecurityHistoryQuery({ q: "  bank.example  ", scope: "IN_SCOPE", risk: "MALICIOUS", page: "3" });
    expect(query).toEqual({ q: "bank.example", scopeDecision: "IN_SCOPE", risk: "MALICIOUS", page: 3 });
    expect(toSecurityAnalysisPageQuery(query)).toEqual({ q: "bank.example", scope_decision: "IN_SCOPE", risk: "MALICIOUS", limit: 10, offset: 20 });
    expect(securityHistoryHref(query)).toBe("/history?q=bank.example&scope=IN_SCOPE&risk=MALICIOUS&page=3");
    expect(parseSecurityHistoryQuery({ scope: "UNKNOWN", risk: "UNKNOWN", page: "-1" })).toEqual({ q: "", scopeDecision: null, risk: null, page: 1 });
  });
});

describe("FE5 case library", () => {
  beforeEach(() => replace.mockReset());

  it("loads, filters and paginates through the server API while updating the URL", async () => {
    const analysis = completedSecurityCase();
    const pageAnalyses = vi.fn().mockResolvedValue(page([analysis], 21));
    render(<CaseLibrary initialQuery={{ q: "", scopeDecision: null, risk: null, page: 1 }} api={api({ pageAnalyses })} />);

    expect(await screen.findByText("21 case")).toBeInTheDocument();
    expect(pageAnalyses).toHaveBeenCalledWith({ limit: 10, offset: 0 });
    expect(screen.getByRole("link", { name: /Mở case/i })).toHaveAttribute("href", `/cases/${analysis.analysis_id}`);

    fireEvent.click(screen.getByRole("button", { name: "Trang sau" }));
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 10 }));
    expect(replace).toHaveBeenLastCalledWith("/history?page=2", { scroll: false });

    fireEvent.change(screen.getByLabelText("Lọc theo quyết định phạm vi"), { target: { value: "IN_SCOPE" } });
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 0, scope_decision: "IN_SCOPE" }));

    fireEvent.change(screen.getByLabelText("Lọc theo mức rủi ro"), { target: { value: "MALICIOUS" } });
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 0, scope_decision: "IN_SCOPE", risk: "MALICIOUS" }));

    fireEvent.change(screen.getByLabelText("Tìm theo thực thể hoặc URL"), { target: { value: "bank.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Tìm case" }));
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 0, q: "bank.example", scope_decision: "IN_SCOPE", risk: "MALICIOUS" }));
    expect(replace).toHaveBeenLastCalledWith("/history?q=bank.example&scope=IN_SCOPE&risk=MALICIOUS", { scroll: false });
  });

  it("supports error retry and a real empty response", async () => {
    const pageAnalyses = vi.fn()
      .mockRejectedValueOnce(new Error("History unavailable"))
      .mockResolvedValueOnce(page([]));
    render(<CaseLibrary initialQuery={{ q: "", scopeDecision: null, risk: null, page: 1 }} api={api({ pageAnalyses })} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("History unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Thử lại" }));
    expect(await screen.findByText("Chưa có case phù hợp")).toBeInTheDocument();
    expect(pageAnalyses).toHaveBeenCalledTimes(2);
  });
});

describe("FE5 case detail and resume", () => {
  beforeEach(() => replace.mockReset());

  it("loads owner-scoped detail, displays retained structure and resumes with exact version", async () => {
    const analysis = completedSecurityCase();
    const next = completedSecurityCase({ analysis_id: "30000000-0000-4000-8000-000000000003", conversation_version: 4 });
    const getConversation = vi.fn().mockResolvedValueOnce(conversation()).mockResolvedValueOnce(conversation(4));
    const createAnalysis = vi.fn().mockResolvedValue(next);
    const client = api({
      getAnalysis: vi.fn().mockResolvedValue(analysis),
      getAnalysisEvents: vi.fn().mockResolvedValue({ contract_version: "v4", events: [], next_cursor: null }),
      getConversation,
      createAnalysis,
    });
    render(<CaseDetail analysisId={analysis.analysis_id} api={client} />);

    expect(await screen.findByRole("heading", { name: "Structured context retained" })).toBeInTheDocument();
    expect(screen.getAllByText("account_verification").length).toBeGreaterThan(0);
    expect(screen.getByText(/Context v3/)).toBeInTheDocument();
    expect(screen.queryByText("Nội dung chat riêng tư không thuộc contract")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Tiếp tục case với thông tin mới"), { target: { value: "Họ vừa yêu cầu gửi OTP" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi follow-up cho case" }));
    await waitFor(() => expect(createAnalysis).toHaveBeenCalledWith({
      message: "Họ vừa yêu cầu gửi OTP",
      conversation_id: analysis.conversation_id,
      conversation_version: 3,
      consent: { external_url_lookup: true },
    }));
    await waitFor(() => expect(replace).toHaveBeenCalledWith(`/cases/${next.analysis_id}`));
  });

  it("refreshes the conversation after a stale-version conflict and preserves the draft", async () => {
    const analysis = completedSecurityCase();
    const getConversation = vi.fn().mockResolvedValueOnce(conversation()).mockResolvedValueOnce(conversation(4));
    const createAnalysis = vi.fn().mockRejectedValue(new ApiError("Version conflict", "CONFLICT", true, 409));
    render(<CaseDetail analysisId={analysis.analysis_id} api={api({
      getAnalysis: vi.fn().mockResolvedValue(analysis),
      getAnalysisEvents: vi.fn().mockResolvedValue({ contract_version: "v4", events: [], next_cursor: null }),
      getConversation,
      createAnalysis,
    })} />);

    const input = await screen.findByLabelText("Tiếp tục case với thông tin mới");
    fireEvent.change(input, { target: { value: "Thông tin cần gửi lại" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi follow-up cho case" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Context version mới đã được tải");
    expect(input).toHaveValue("Thông tin cần gửi lại");
    expect(screen.getByText(/Context v4/)).toBeInTheDocument();
  });

  it("gives a clear owner/not-found path and a new-case action", async () => {
    const analysisId = completedSecurityCase().analysis_id;
    render(<CaseDetail analysisId={analysisId} api={api({
      getAnalysis: vi.fn().mockRejectedValue(new ApiError("Forbidden", "FORBIDDEN", false, 403)),
    })} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("không có quyền mở analysis");
    expect(screen.getByRole("link", { name: "Bắt đầu case mới" })).toHaveAttribute("href", "/");
  });
});
