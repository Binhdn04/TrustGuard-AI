import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CaseDetail } from "@/components/cases/case-detail";
import { CaseLibrary } from "@/components/cases/case-library";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { ApiError } from "@/lib/api/api-error";
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
    decideAdminReport: vi.fn(), listAdminAppeals: vi.fn(), decideAdminAppeal: vi.fn(), createBrand: vi.fn(), createBrandVersion: vi.fn(),
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
    const pageAnalyses = vi.fn().mockResolvedValue(page([analysis], 451));
    render(<CaseLibrary initialQuery={{ q: "", scopeDecision: null, risk: null, page: 1 }} api={api({ pageAnalyses })} />);

    expect(await screen.findByText("451 cuộc trò chuyện")).toBeInTheDocument();
    expect(pageAnalyses).toHaveBeenCalledWith({ limit: 10, offset: 0 });
    expect(screen.getByRole("link", { name: /Mở cuộc trò chuyện/i })).toHaveAttribute("href", `/cases/${analysis.analysis_id}`);
    expect(screen.getByText("Kiểm tra một liên kết liên quan đến ACME Bank")).toBeInTheDocument();
    expect(screen.queryByText(analysis.analysis_id.slice(0, 8))).not.toBeInTheDocument();
    expect(screen.queryByText(/evidence/i)).not.toBeInTheDocument();
    expect(screen.queryByText(analysis.explanation!)).not.toBeInTheDocument();
    expect(screen.queryByText(analysis.security_context!.urls[0])).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Trang 1" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Trang 46" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Trang sau" }));
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 10 }));
    expect(replace).toHaveBeenLastCalledWith("/history?page=2", { scroll: false });

    fireEvent.click(screen.getByRole("button", { name: "Trang 3" }));
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 20 }));
    expect(replace).toHaveBeenLastCalledWith("/history?page=3", { scroll: false });

    fireEvent.change(screen.getByLabelText("Lọc theo quyết định phạm vi"), { target: { value: "IN_SCOPE" } });
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 0, scope_decision: "IN_SCOPE" }));

    fireEvent.change(screen.getByLabelText("Lọc theo mức rủi ro"), { target: { value: "MALICIOUS" } });
    await waitFor(() => expect(pageAnalyses).toHaveBeenLastCalledWith({ limit: 10, offset: 0, scope_decision: "IN_SCOPE", risk: "MALICIOUS" }));

    fireEvent.change(screen.getByLabelText("Tìm theo tổ chức hoặc website"), { target: { value: "bank.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Tìm" }));
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
    expect(await screen.findByText("Chưa có cuộc trò chuyện phù hợp")).toBeInTheDocument();
    expect(pageAnalyses).toHaveBeenCalledTimes(2);
  });

  it("replaces the visible history when search and filters change", async () => {
    const acme = completedSecurityCase();
    const communitySite = completedSecurityCase({
      analysis_id: "20000000-0000-4000-8000-000000000002",
      risk: "SAFE",
      security_context: {
        ...completedSecurityCase().security_context!,
        claimed_entity: "Chống Lừa Đảo",
        urls: ["https://chongluadao.vn/"],
      },
    });
    const records = [acme, communitySite];
    const pageAnalyses = vi.fn().mockImplementation(async (query: {
      q?: string;
      scope_decision?: SecurityScopeResponseV4["scope_decision"];
      risk?: SecurityScopeResponseV4["risk"];
      limit?: number;
      offset?: number;
    }) => {
      const needle = query.q?.toLocaleLowerCase("vi-VN");
      const items = records.filter((item) => (
        (!query.scope_decision || item.scope_decision === query.scope_decision)
        && (!query.risk || item.risk === query.risk)
        && (!needle || [item.security_context?.claimed_entity, ...(item.security_context?.urls ?? [])]
          .some((value) => value?.toLocaleLowerCase("vi-VN").includes(needle)))
      ));
      return page(items, items.length, query.offset ?? 0);
    });
    render(<CaseLibrary initialQuery={{ q: "", scopeDecision: null, risk: null, page: 1 }} api={api({ pageAnalyses })} />);

    expect(await screen.findAllByRole("link", { name: /Mở cuộc trò chuyện/i })).toHaveLength(2);

    fireEvent.change(screen.getByLabelText("Lọc theo mức rủi ro"), { target: { value: "SAFE" } });
    await waitFor(() => expect(screen.getAllByRole("link", { name: /Mở cuộc trò chuyện/i })).toHaveLength(1));
    expect(screen.getByText(/Chống Lừa Đảo/)).toBeInTheDocument();
    expect(screen.queryByText(/ACME Bank/)).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Lọc theo mức rủi ro"), { target: { value: "" } });
    await waitFor(() => expect(screen.getAllByRole("link", { name: /Mở cuộc trò chuyện/i })).toHaveLength(2));
    fireEvent.change(screen.getByLabelText("Tìm theo tổ chức hoặc website"), { target: { value: "ACME" } });
    fireEvent.click(screen.getByRole("button", { name: "Tìm" }));

    await waitFor(() => expect(screen.getAllByRole("link", { name: /Mở cuộc trò chuyện/i })).toHaveLength(1));
    expect(screen.getByText(/ACME Bank/)).toBeInTheDocument();
    expect(screen.queryByText(/Chống Lừa Đảo/)).not.toBeInTheDocument();
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

    expect(await screen.findByRole("heading", { name: "Tiếp tục cuộc trò chuyện" })).toBeInTheDocument();
    screen.getAllByText("account_verification").forEach((item) => expect(item).not.toBeVisible());
    fireEvent.click(screen.getByRole("button", { name: "Kỹ thuật" }));
    expect(screen.getByRole("heading", { name: "Ngữ cảnh có cấu trúc được giữ lại" })).toBeInTheDocument();
    expect(screen.getAllByText("account_verification").length).toBeGreaterThan(0);
    expect(screen.getByText(/Ngữ cảnh v3/)).toBeInTheDocument();
    expect(screen.queryByText("Nội dung chat riêng tư không thuộc contract")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Tiếp tục lượt kiểm tra với thông tin mới"), { target: { value: "Họ vừa yêu cầu gửi OTP" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi thông tin bổ sung cho lượt kiểm tra" }));
    await waitFor(() => expect(createAnalysis).toHaveBeenCalledWith({
      message: "Họ vừa yêu cầu gửi OTP",
      conversation_id: analysis.conversation_id,
      conversation_version: 3,
      consent: { external_url_lookup: true, official_source_lookup: true },
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

    const input = await screen.findByLabelText("Tiếp tục lượt kiểm tra với thông tin mới");
    fireEvent.change(input, { target: { value: "Thông tin cần gửi lại" } });
    fireEvent.click(screen.getByRole("button", { name: "Gửi thông tin bổ sung cho lượt kiểm tra" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Phiên bản ngữ cảnh mới đã được tải");
    expect(input).toHaveValue("Thông tin cần gửi lại");
    fireEvent.click(screen.getByRole("button", { name: "Kỹ thuật" }));
    expect(screen.getByText(/Ngữ cảnh v4/)).toBeInTheDocument();
  });

  it("gives a clear owner/not-found path and a new-case action", async () => {
    const analysisId = completedSecurityCase().analysis_id;
    render(<CaseDetail analysisId={analysisId} api={api({
      getAnalysis: vi.fn().mockRejectedValue(new ApiError("Forbidden", "FORBIDDEN", false, 403)),
    })} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("không có quyền mở lượt kiểm tra");
    expect(screen.getByRole("link", { name: "Bắt đầu lượt kiểm tra mới" })).toHaveAttribute("href", "/");
  });

  it("uses the same safe handoff path for a deleted or expired case", async () => {
    const analysisId = completedSecurityCase().analysis_id;
    render(<CaseDetail analysisId={analysisId} api={api({
      getAnalysis: vi.fn().mockRejectedValue(new ApiError("Not found", "NOT_FOUND", false, 404)),
    })} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("không tồn tại hoặc không còn khả dụng");
    expect(screen.getByRole("link", { name: "Bắt đầu lượt kiểm tra mới" })).toHaveAttribute("href", "/");
  });
});
