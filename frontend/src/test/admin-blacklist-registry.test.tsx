import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { BlacklistRegistry } from "@/components/admin/trust/blacklist-registry";
import { ApiError } from "@/lib/api/api-error";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type {
  SecurityBlacklistActionProposalV4,
  SecurityBlacklistAuditRecordV4,
  SecurityBlacklistDecisionResponseV4,
  SecurityBlacklistRecordV4,
} from "@/types/generated/api-v4";

const record: SecurityBlacklistRecordV4 = {
  contract_version: "v4",
  blacklist_id: "blacklist-1",
  canonical_domain: "fraud.example",
  lifecycle: "active",
  enabling_action_id: "action-add",
  disabling_action_id: null,
  reason: "Credential theft",
  provenance: "Reviewed user report",
  evidence_refs: ["evidence:credential-form"],
  created_at: "2026-08-24T08:00:00Z",
  updated_at: "2026-08-24T08:00:00Z",
  version: 1,
};

const proposal: SecurityBlacklistActionProposalV4 = {
  contract_version: "v4",
  action_id: "action-add",
  action: "add_to_blacklist",
  canonical_domain: "fraud.example",
  status: "pending_review",
  source_analysis_id: null,
  source_report_id: null,
  proposed_at: "2026-08-24T08:00:00Z",
};

function decision(status: SecurityBlacklistDecisionResponseV4["status"]): SecurityBlacklistDecisionResponseV4 {
  return {
    contract_version: "v4",
    action_id: "action-add",
    action: "add_to_blacklist",
    status,
    record: status === "executed" ? record : null,
    reviewed_at: "2026-08-24T08:01:00Z",
    executed_at: status === "executed" ? "2026-08-24T08:01:01Z" : null,
    execution_error: status === "failed" ? "BLACKLIST_WRITE_FAILED" : null,
  };
}

function api(overrides: Partial<SecurityAnalysisApi> = {}): SecurityAnalysisApi {
  return {
    pageBlacklist: vi.fn().mockResolvedValue({ contract_version: "v4", items: [], total: 0, limit: 10, offset: 0 }),
    proposeBlacklist: vi.fn().mockResolvedValue(proposal),
    proposeDisableBlacklist: vi.fn().mockResolvedValue({ ...proposal, action_id: "action-disable", action: "disable_blacklist" }),
    decideBlacklistAction: vi.fn().mockResolvedValue(decision("executed")),
    listBlacklistAudit: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as unknown as SecurityAnalysisApi;
}

async function fillCreateForm() {
  fireEvent.click(screen.getByRole("button", { name: "Thêm domain cần chặn" }));
  fireEvent.change(screen.getByLabelText("Domain cần chặn"), { target: { value: "Fraud.Example." } });
  fireEvent.change(screen.getByLabelText("Provenance danh sách chặn"), { target: { value: "Reviewed user report" } });
  fireEvent.change(screen.getByLabelText("Lý do chặn"), { target: { value: "Credential theft" } });
  fireEvent.change(screen.getByLabelText("Nguồn bằng chứng chặn"), { target: { value: "evidence:credential-form, report:42" } });
  fireEvent.click(screen.getByRole("button", { name: "Xem trước domain chuẩn hóa" }));
  expect(screen.getByRole("dialog")).toHaveTextContent("fraud.example");
}

describe("M5 blacklist registry", () => {
  it("creates a proposal and reports success only after an executed decision", async () => {
    const proposeBlacklist = vi.fn().mockResolvedValue(proposal);
    const decideBlacklistAction = vi.fn().mockResolvedValue(decision("executed"));
    render(<BlacklistRegistry api={api({ proposeBlacklist, decideBlacklistAction })} />);
    await screen.findByText("Không có domain phù hợp.");

    await fillCreateForm();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận chặn" }));

    await waitFor(() => expect(proposeBlacklist).toHaveBeenCalledWith({
      canonical_domain: "fraud.example",
      reason: "Credential theft",
      provenance: "Reviewed user report",
      evidence_refs: ["evidence:credential-form", "report:42"],
    }));
    expect(decideBlacklistAction).toHaveBeenCalledWith("action-add", { decision: "approved", note: "Credential theft" });
    expect(await screen.findByRole("status")).toHaveTextContent("Đã chặn fraud.example");
  });

  it.each(["rejected", "failed"] as const)("does not show success when the reviewed action is %s", async (status) => {
    render(<BlacklistRegistry api={api({ decideBlacklistAction: vi.fn().mockResolvedValue(decision(status)) })} />);
    await screen.findByText("Không có domain phù hợp.");
    await fillCreateForm();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận chặn" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(status === "failed" ? "BLACKLIST_WRITE_FAILED" : "Đã từ chối");
    expect(screen.queryByText(/^Đã chặn fraud\.example/)).not.toBeInTheDocument();
  });

  it("shows duplicate conflicts without automatically retrying the proposal", async () => {
    const proposeBlacklist = vi.fn().mockRejectedValue(new ApiError("duplicate", "CONFLICT", false, 409));
    render(<BlacklistRegistry api={api({ proposeBlacklist })} />);
    await screen.findByText("Không có domain phù hợp.");
    await fillCreateForm();
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận chặn" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("không tự gửi lại quyết định");
    expect(proposeBlacklist).toHaveBeenCalledTimes(1);
  });

  it("disables an active record through proposal, reviewed decision and immutable audit", async () => {
    const pageBlacklist = vi.fn().mockResolvedValue({ contract_version: "v4", items: [record], total: 1, limit: 10, offset: 0 });
    const proposeDisableBlacklist = vi.fn().mockResolvedValue({ ...proposal, action_id: "action-disable", action: "disable_blacklist" });
    const decideBlacklistAction = vi.fn().mockResolvedValue({ ...decision("executed"), action_id: "action-disable", action: "disable_blacklist", record: { ...record, lifecycle: "disabled" } });
    const audit: SecurityBlacklistAuditRecordV4 = {
      contract_version: "v4",
      decision_id: "decision-1",
      action_id: "action-add",
      decision: "approved",
      action: "add_to_blacklist",
      status: "executed",
      note: "Credential theft",
      evidence_refs: record.evidence_refs,
      decided_at: "2026-08-24T08:01:00Z",
      execution_error: null,
    };
    const listBlacklistAudit = vi.fn().mockResolvedValue([audit]);
    render(<BlacklistRegistry api={api({ pageBlacklist, proposeDisableBlacklist, decideBlacklistAction, listBlacklistAudit })} />);
    await screen.findByText("fraud.example");

    fireEvent.click(screen.getByRole("button", { name: "Xem lịch sử" }));
    expect(await screen.findByText("Credential theft", { selector: "article p" })).toBeInTheDocument();
    expect(listBlacklistAudit).toHaveBeenCalledWith("blacklist-1");
    fireEvent.click(screen.getByRole("button", { name: "Đóng lịch sử" }));
    fireEvent.click(screen.getByRole("button", { name: "Vô hiệu hóa" }));
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận vô hiệu hóa" }));

    await waitFor(() => expect(proposeDisableBlacklist).toHaveBeenCalledWith("blacklist-1", expect.objectContaining({
      provenance: "blacklist-record:blacklist-1",
    })));
    expect(decideBlacklistAction).toHaveBeenCalledWith("action-disable", expect.objectContaining({ decision: "approved" }));
  });
});
