import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ReviewRoom } from "@/components/admin/review-room/review-room";
import { ApiError } from "@/lib/api/api-error";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityReportAdminRecordV4 } from "@/types/generated/api-v4";
import type { SecurityAppealAdminRecordV4 } from "@/types/generated/api-v4";

import { completedSecurityCase } from "./fixtures/security-case-v4";

const auth = vi.hoisted(() => ({ role: "security_admin" as "security_admin" | "user", loading: false }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: auth.role },
    isLoading: auth.loading,
  }),
}));

const report: SecurityReportAdminRecordV4 = {
  contract_version: "v4",
  report_id: "20000000-0000-4000-8000-000000000002",
  analysis_id: completedSecurityCase().analysis_id,
  owner_id: "owner-1",
  reason: "The verdict needs a human review",
  comment: "Please verify the evidence chain.",
  status: "submitted",
  decision: null,
  resolution: null,
  remediation_action: "none",
  whitelist_entry: null,
  blacklist_proposal: null,
  remediation_status: "not_requested",
  remediation_reference: null,
  reviewer_id: null,
  review_note: null,
  created_at: "2026-08-13T09:00:00Z",
  reviewed_at: null,
};

const appeal: SecurityAppealAdminRecordV4 = {
  contract_version: "v4",
  appeal_id: "30000000-0000-4000-8000-000000000003",
  analysis_id: completedSecurityCase().analysis_id,
  owner_id: "owner-1",
  reason: "The risk decision may be incorrect",
  comment: "Please reconsider against the recorded evidence.",
  status: "submitted",
  outcome: null,
  resolution_note: null,
  reviewer_id: null,
  created_at: "2026-08-13T09:02:00Z",
  resolved_at: null,
};

function securityClient(overrides: Partial<SecurityAnalysisApi> = {}): SecurityAnalysisApi {
  return {
    listAdminReports: vi.fn().mockResolvedValue({ contract_version: "v4", items: [report], total: 1, limit: 10, offset: 0 }),
    listAdminAppeals: vi.fn().mockResolvedValue({ contract_version: "v4", items: [], total: 0, limit: 10, offset: 0 }),
    getAdminAnalysis: vi.fn().mockResolvedValue(completedSecurityCase()),
    decideAdminReport: vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved", reviewer_id: "admin-1", review_note: "Evidence chain verified", reviewed_at: "2026-08-13T09:10:00Z" }),
    decideAdminAppeal: vi.fn(),
    ...overrides,
  } as unknown as SecurityAnalysisApi;
}

describe("FE7 Security Review Room", () => {
  beforeEach(() => { auth.role = "security_admin"; auth.loading = false; });

  it("blocks regular users before any admin API request", () => {
    auth.role = "user";
    const securityApi = securityClient();
    render(<ReviewRoom securityApi={securityApi} />);

    expect(screen.getByRole("heading", { name: "Cần quyền quản trị" })).toBeInTheDocument();
    expect(securityApi.listAdminReports).not.toHaveBeenCalled();
    expect(securityApi.getAdminAnalysis).not.toHaveBeenCalled();
  });

  it("loads structured case evidence before enabling a noted report decision", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved", reviewer_id: "admin-1", review_note: "Evidence chain verified", reviewed_at: "2026-08-13T09:10:00Z" });
    const securityApi = securityClient({ decideAdminReport });
    render(<ReviewRoom securityApi={securityApi} />);

    const reportButton = await screen.findByRole("button", { name: new RegExp(report.reason) });
    fireEvent.click(reportButton);

    expect(await screen.findByRole("heading", { name: "Rủi ro cao" })).toBeInTheDocument();
    expect(screen.getByText("URL asks for account credentials.")).toBeInTheDocument();
    expect(screen.getByText(/Provider reputation was unavailable\./)).toBeInTheDocument();
    expect(securityApi.getAdminAnalysis).toHaveBeenCalledWith(report.analysis_id);

    const submit = screen.getByRole("button", { name: "Xác nhận quyết định" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Evidence chain verified" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, {
      decision: "approved",
      resolution: "no_change",
      remediation_action: "none",
      evidence_refs: completedSecurityCase().explanation_evidence_refs,
      note: "Evidence chain verified",
    }));
    expect(await screen.findByText("Quyết định đã ghi")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Xác nhận quyết định" })).not.toBeInTheDocument();
  });

  it("shows a non-executing grounded copilot suggestion without filling the HITL note", async () => {
    const draftAdminCopilot = vi.fn().mockResolvedValue({
      contract_version: "v4", suggestion_id: "40000000-0000-4000-8000-000000000004",
      analysis_id: report.analysis_id, evidence_summary: "Credential evidence supports manual review.",
      conflicts: [], missing_information: [], related_reviewed_campaigns: [],
      proposed_disposition: "confirm_malicious", proposed_admin_action: "block_domain",
      action_executable: false, executed: false,
      grounded_rationale: [{ text: "Credential request is recorded.", evidence_refs: ["evidence:0123456789abcdef"] }],
      evidence_refs: ["evidence:0123456789abcdef"], provider: "fake", model: "admin-v1",
      suggestion_version: "security-admin-copilot-v1", generation_mode: "ai",
      usage: { input_tokens: 10, output_tokens: 5, cost_usd: 0, status: "ok" },
      generated_at: "2026-08-15T09:00:00Z",
    });
    render(<ReviewRoom securityApi={securityClient({ draftAdminCopilot })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    fireEvent.click(await screen.findByRole("button", { name: "Tạo gợi ý" }));

    expect(await screen.findByText("Credential evidence supports manual review.")).toBeInTheDocument();
    expect(screen.getByLabelText("Gợi ý AI — không tự thực thi")).toHaveTextContent("Không tự thực thi");
    expect(screen.getByLabelText("Ghi chú của người duyệt")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Xác nhận quyết định" })).toBeDisabled();
    expect(draftAdminCopilot).toHaveBeenCalledWith(report.analysis_id, { refresh: false });
  });

  it("presents a 409 as a terminal concurrency conflict and reloads the queue", async () => {
    const listAdminReports = vi.fn().mockResolvedValue({ contract_version: "v4", items: [report], total: 1, limit: 10, offset: 0 });
    const decideAdminReport = vi.fn().mockRejectedValue(new ApiError("Already processed", "CONFLICT", false, 409));
    const securityApi = securityClient({ listAdminReports, decideAdminReport });
    render(<ReviewRoom securityApi={securityApi} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "My review note" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("người duyệt khác xử lý");
    await waitFor(() => expect(listAdminReports.mock.calls.length).toBeGreaterThanOrEqual(2));
    expect(decideAdminReport).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Xác nhận quyết định" })).toBeDisabled();
  });

  it("uses the same loaded case boundary for an appeal decision", async () => {
    const decideAdminAppeal = vi.fn().mockResolvedValue({ ...appeal, status: "resolved", outcome: "overturn", resolution_note: "Evidence warrants overturn", reviewer_id: "admin-1", resolved_at: "2026-08-13T09:12:00Z" });
    const securityApi = securityClient({
      listAdminAppeals: vi.fn().mockResolvedValue({ contract_version: "v4", items: [appeal], total: 1, limit: 10, offset: 0 }),
      decideAdminAppeal,
    });
    render(<ReviewRoom securityApi={securityApi} />);

    fireEvent.click(screen.getByRole("tab", { name: "Khiếu nại" }));
    fireEvent.click(await screen.findByRole("button", { name: new RegExp(appeal.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Quyết định"), { target: { value: "overturn" } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Evidence warrants overturn" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminAppeal).toHaveBeenCalledWith(appeal.appeal_id, { outcome: "overturn", note: "Evidence warrants overturn" }));
    expect(await screen.findByText("Quyết định đã ghi")).toBeInTheDocument();
  });

  it("creates then explicitly reviews a blacklist proposal for a malicious conclusion", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({
      ...report,
      status: "processed",
      decision: "approved",
      resolution: "confirm_malicious",
      remediation_action: "propose_blacklist",
      remediation_status: "pending",
      remediation_reference: { admin_action_id: "action-report-block" },
      reviewer_id: "admin-1",
      review_note: "Credential theft confirmed",
      reviewed_at: "2026-08-13T09:10:00Z",
    });
    const decideBlacklistAction = vi.fn().mockResolvedValue({
      contract_version: "v4",
      action_id: "action-report-block",
      action: "add_to_blacklist",
      status: "executed",
      record: null,
      reviewed_at: "2026-08-13T09:11:00Z",
      executed_at: "2026-08-13T09:11:00Z",
      execution_error: null,
    });
    render(<ReviewRoom securityApi={securityClient({ decideAdminReport, decideBlacklistAction })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Kết luận báo cáo"), { target: { value: "confirm_malicious" } });
    fireEvent.change(screen.getByLabelText("Lý do chặn trong hành động khắc phục"), { target: { value: "Credential theft confirmed" } });
    fireEvent.change(screen.getByLabelText("Nguồn xác minh hành động khắc phục"), { target: { value: "Reviewed report evidence" } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Credential theft confirmed" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, expect.objectContaining({
      decision: "approved",
      resolution: "confirm_malicious",
      remediation_action: "propose_blacklist",
      blacklist_proposal: expect.objectContaining({
        reason: "Credential theft confirmed",
        provenance: "Reviewed report evidence",
      }),
    })));
    expect(screen.getByText("Đề xuất chặn đang chờ quyết định riêng")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận thực thi chặn" }));
    await waitFor(() => expect(decideBlacklistAction).toHaveBeenCalledWith("action-report-block", {
      decision: "approved",
      note: expect.stringContaining(report.report_id),
    }));
    expect(await screen.findByText(/Đề xuất chặn domain · Đã thực thi/)).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /Hành động chờ duyệt/i })).not.toBeInTheDocument();
  });

  it("maps safe and false-positive conclusions to memory or a scoped whitelist entry", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved" });
    render(<ReviewRoom securityApi={securityClient({ decideAdminReport })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Kết luận báo cáo"), { target: { value: "mark_false_positive" } });
    fireEvent.change(screen.getByLabelText("Hành động khắc phục"), { target: { value: "add_to_whitelist" } });
    fireEvent.change(screen.getByLabelText("Domain thêm vào danh sách tin cậy"), { target: { value: "safe.example" } });
    fireEvent.change(screen.getByLabelText("Nguồn xác minh hành động khắc phục"), { target: { value: "Official security contact" } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "False positive verified" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, expect.objectContaining({
      resolution: "mark_false_positive",
      remediation_action: "add_to_whitelist",
      whitelist_entry: expect.objectContaining({
        indicator: "safe.example",
        scope: "domain",
        provenance: "Official security contact",
        policy_version: "whitelist-v1",
      }),
    })));
  });

  it("maps a confirmed-safe conclusion to reviewed Memory without list mutation", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved" });
    render(<ReviewRoom securityApi={securityClient({ decideAdminReport })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Kết luận báo cáo"), { target: { value: "confirm_safe" } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Safe evidence verified" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, expect.objectContaining({
      decision: "approved",
      resolution: "confirm_safe",
      remediation_action: "update_memory",
    })));
  });

  it.each(["rejected", "dismissed"] as const)("submits %s without resolution or remediation side effects", async (decision) => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision });
    render(<ReviewRoom securityApi={securityClient({ decideAdminReport })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Quyết định"), { target: { value: decision } });
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "No trusted remediation is justified" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, expect.objectContaining({
      decision,
      resolution: undefined,
      remediation_action: "none",
    })));
  });

  it("does not offer trust or block mutation for a needs-more-information conclusion", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved" });
    render(<ReviewRoom securityApi={securityClient({ decideAdminReport })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Kết luận báo cáo"), { target: { value: "needs_more_information" } });
    expect(screen.queryByLabelText("Hành động khắc phục")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Domain thêm vào danh sách tin cậy")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Domain cần chặn trong hành động khắc phục")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Need the original message headers" } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận quyết định" }));

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, expect.objectContaining({
      resolution: "needs_more_information",
      remediation_action: "none",
    })));
  });

  it("renders remediation failure as failure, not as a successful terminal action", async () => {
    const failedReport: SecurityReportAdminRecordV4 = {
      ...report,
      status: "processed",
      decision: "approved",
      resolution: "confirm_malicious",
      remediation_action: "propose_blacklist",
      remediation_status: "failed",
      remediation_reference: { admin_action_id: "action-failed" },
      reviewer_id: "admin-1",
      review_note: "Evidence confirmed",
      reviewed_at: "2026-08-24T09:00:00Z",
    };
    render(<ReviewRoom securityApi={securityClient({
      listAdminReports: vi.fn().mockResolvedValue({ contract_version: "v4", items: [failedReport], total: 1, limit: 10, offset: 0 }),
    })} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(failedReport.reason) }));
    expect(await screen.findByText(/Đề xuất chặn domain · Thất bại/)).toBeInTheDocument();
    expect(screen.getByText(/action-failed/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Xác nhận quyết định" })).not.toBeInTheDocument();
  });
});
