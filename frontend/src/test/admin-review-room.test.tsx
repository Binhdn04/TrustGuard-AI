import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ReviewRoom } from "@/components/admin/review-room/review-room";
import type { AdminActionApi } from "@/components/admin/review-room/action-execution-panel";
import { ApiError } from "@/lib/api/api-error";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { AdminActionRecordV3 } from "@/types/generated/api-v3";
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

function actionClient(overrides: Partial<AdminActionApi> = {}): AdminActionApi {
  return {
    listAdminActions: vi.fn().mockResolvedValue({ contract_version: "v3", items: [], total: 0, limit: 10, offset: 0 }),
    getAdminAction: vi.fn(),
    listAdminActionAudit: vi.fn().mockResolvedValue([]),
    decideAdminAction: vi.fn(),
    ...overrides,
  } as AdminActionApi;
}

describe("FE7 Security Review Room", () => {
  beforeEach(() => { auth.role = "security_admin"; auth.loading = false; });

  it("blocks regular users before any admin API request", () => {
    auth.role = "user";
    const securityApi = securityClient();
    render(<ReviewRoom securityApi={securityApi} actionApi={actionClient()} />);

    expect(screen.getByRole("heading", { name: "Cần quyền quản trị" })).toBeInTheDocument();
    expect(securityApi.listAdminReports).not.toHaveBeenCalled();
    expect(securityApi.getAdminAnalysis).not.toHaveBeenCalled();
  });

  it("loads structured case evidence before enabling a noted report decision", async () => {
    const decideAdminReport = vi.fn().mockResolvedValue({ ...report, status: "processed", decision: "approved", reviewer_id: "admin-1", review_note: "Evidence chain verified", reviewed_at: "2026-08-13T09:10:00Z" });
    const securityApi = securityClient({ decideAdminReport });
    render(<ReviewRoom securityApi={securityApi} actionApi={actionClient()} />);

    const reportButton = await screen.findByRole("button", { name: new RegExp(report.reason) });
    fireEvent.click(reportButton);

    expect(await screen.findByRole("heading", { name: "Rủi ro cao" })).toBeInTheDocument();
    expect(screen.getByText("URL asks for account credentials.")).toBeInTheDocument();
    expect(screen.getByText(/Provider reputation was unavailable\./)).toBeInTheDocument();
    expect(securityApi.getAdminAnalysis).toHaveBeenCalledWith(report.analysis_id);

    const submit = screen.getByRole("button", { name: "Submit reviewed decision" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reviewer note"), { target: { value: "Evidence chain verified" } });
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() => expect(decideAdminReport).toHaveBeenCalledWith(report.report_id, { decision: "approved", note: "Evidence chain verified" }));
    expect(await screen.findByText("Terminal review")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Submit reviewed decision" })).not.toBeInTheDocument();
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
    render(<ReviewRoom securityApi={securityClient({ draftAdminCopilot })} actionApi={actionClient()} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    fireEvent.click(await screen.findByRole("button", { name: "Tạo gợi ý" }));

    expect(await screen.findByText("Credential evidence supports manual review.")).toBeInTheDocument();
    expect(screen.getByLabelText("AI suggestion — not executed")).toHaveTextContent("Không tự thực thi");
    expect(screen.getByLabelText("Reviewer note")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Submit reviewed decision" })).toBeDisabled();
    expect(draftAdminCopilot).toHaveBeenCalledWith(report.analysis_id, { refresh: false });
  });

  it("presents a 409 as a terminal concurrency conflict and reloads the queue", async () => {
    const listAdminReports = vi.fn().mockResolvedValue({ contract_version: "v4", items: [report], total: 1, limit: 10, offset: 0 });
    const decideAdminReport = vi.fn().mockRejectedValue(new ApiError("Already processed", "CONFLICT", false, 409));
    const securityApi = securityClient({ listAdminReports, decideAdminReport });
    render(<ReviewRoom securityApi={securityApi} actionApi={actionClient()} />);

    fireEvent.click(await screen.findByRole("button", { name: new RegExp(report.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Reviewer note"), { target: { value: "My review note" } });
    fireEvent.click(screen.getByRole("button", { name: "Submit reviewed decision" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("reviewer khác xử lý");
    await waitFor(() => expect(listAdminReports.mock.calls.length).toBeGreaterThanOrEqual(2));
    expect(decideAdminReport).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Submit reviewed decision" })).toBeDisabled();
  });

  it("uses the same loaded case boundary for an appeal decision", async () => {
    const decideAdminAppeal = vi.fn().mockResolvedValue({ ...appeal, status: "resolved", outcome: "overturn", resolution_note: "Evidence warrants overturn", reviewer_id: "admin-1", resolved_at: "2026-08-13T09:12:00Z" });
    const securityApi = securityClient({
      listAdminAppeals: vi.fn().mockResolvedValue({ contract_version: "v4", items: [appeal], total: 1, limit: 10, offset: 0 }),
      decideAdminAppeal,
    });
    render(<ReviewRoom securityApi={securityApi} actionApi={actionClient()} />);

    fireEvent.click(screen.getByRole("tab", { name: "Appeals" }));
    fireEvent.click(await screen.findByRole("button", { name: new RegExp(appeal.reason) }));
    await screen.findByRole("heading", { name: "Rủi ro cao" });
    fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "overturn" } });
    fireEvent.change(screen.getByLabelText("Reviewer note"), { target: { value: "Evidence warrants overturn" } });
    fireEvent.click(screen.getByRole("button", { name: "Submit reviewed decision" }));

    await waitFor(() => expect(decideAdminAppeal).toHaveBeenCalledWith(appeal.appeal_id, { outcome: "overturn", note: "Evidence warrants overturn" }));
    expect(await screen.findByText("Terminal review")).toBeInTheDocument();
  });

  it("shows missing action sink as failed execution, never as success", async () => {
    const pending: AdminActionRecordV3 = {
      contract_version: "v3", action_id: "action-1", analysis_id: null,
      security_analysis_id: report.analysis_id, campaign_id: null, action: "add_to_blacklist",
      target: "fraud.example", status: "pending_review",
      evidence_snapshot: [{ type: "domain_reputation", source: "provider", title: "Known malicious host", url: "https://fraud.example", finding: "Listed by provider", observed_at: "2026-08-13T09:00:00Z" }],
      proposed_at: "2026-08-13T09:00:00Z", reviewer_id: null, review_note: null,
      reviewed_at: null, executed_at: null, execution_error: null,
    };
    const failed: AdminActionRecordV3 = { ...pending, status: "failed", reviewer_id: "admin-1", review_note: "Evidence confirmed", reviewed_at: "2026-08-13T09:10:00Z", executed_at: "2026-08-13T09:10:01Z", execution_error: "ACTION_SINK_NOT_CONFIGURED" };
    const getAdminAction = vi.fn().mockResolvedValueOnce(pending).mockResolvedValueOnce(failed);
    const decideAdminAction = vi.fn().mockResolvedValue({ contract_version: "v3", action_id: pending.action_id, decision_id: "decision-1", action: pending.action, status: "failed", reviewed_at: failed.reviewed_at, executed_at: failed.executed_at, execution_error: failed.execution_error });
    const actions = actionClient({
      listAdminActions: vi.fn().mockResolvedValue({ contract_version: "v3", items: [pending], total: 1, limit: 10, offset: 0 }),
      getAdminAction,
      decideAdminAction,
    });
    render(<ReviewRoom securityApi={securityClient()} actionApi={actions} />);

    fireEvent.click(screen.getByRole("tab", { name: /Hành động chờ duyệt/i }));
    fireEvent.click(await screen.findByRole("button", { name: /add to blacklist/i }));
    expect(await screen.findByText("Known malicious host")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Reviewer note"), { target: { value: "Evidence confirmed" } });
    fireEvent.click(screen.getByRole("button", { name: "Submit action decision" }));

    expect(await screen.findByText(/Execution failed: ACTION_SINK_NOT_CONFIGURED/)).toBeInTheDocument();
    expect(screen.queryByText(/Execution completed at/)).not.toBeInTheDocument();
    expect(decideAdminAction).toHaveBeenCalledWith("action-1", { decision: "approved", note: "Evidence confirmed" });
  });
});
