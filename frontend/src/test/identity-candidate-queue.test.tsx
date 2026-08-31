import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { IdentityCandidateQueue } from "@/components/admin/trust/identity-candidate-queue";
import type { IdentityCandidateV4 } from "@/types/generated/api-v4";

const candidate: IdentityCandidateV4 = {
  association_id: "10000000-0000-4000-8000-000000000001",
  entity_name: "Bệnh viện Đại học Y Hà Nội",
  canonical_url: "https://benhviendaihocyhanoi.isofhcare.vn/dang-ky",
  canonical_domain: "benhviendaihocyhanoi.isofhcare.vn",
  relationship: "endorsed_third_party_service", assurance: "verified", confidence: 0.86,
  evidence_refs: ["identity-evidence:aaaaaaaaaaaaaaaa", "identity-evidence:bbbbbbbbbbbbbbbb"],
  discovered_at: "2026-08-21T08:00:00Z", verified_at: "2026-08-21T08:00:00Z",
  expires_at: "2026-08-28T08:00:00Z", policy_version: "identity-discovery-v2",
  version: 1, supersedes: null, terminal_decision_id: null,
  observations: [
    { evidence_ref: "identity-evidence:aaaaaaaaaaaaaaaa", family: "exact_resource_endorsement", source_host: "hospital.example", canonical_url: "https://hospital.example/services", content_hash: "a".repeat(64), observed_at: "2026-08-21T08:00:00Z" },
    { evidence_ref: "identity-evidence:bbbbbbbbbbbbbbbb", family: "target_resource_match", source_host: "benhviendaihocyhanoi.isofhcare.vn", canonical_url: "https://benhviendaihocyhanoi.isofhcare.vn/dang-ky", content_hash: "b".repeat(64), observed_at: "2026-08-21T08:00:00Z" },
  ],
};

describe("IdentityCandidateQueue", () => {
  it("shows evidence and requires a reviewer note before approval", async () => {
    const onDecide = vi.fn().mockResolvedValue(undefined);
    render(<IdentityCandidateQueue page={{ contract_version: "v4", items: [candidate], total: 1, limit: 10, offset: 0 }} query={{ entity: "", status: "all", relationship: "all", page: 1 }} loading={false} busy={false} error={null} onQueryChange={vi.fn()} onCreateManual={vi.fn()} onDecide={onDecide} onRetry={vi.fn()} />);

    expect(screen.getByText(/exact_resource_endorsement/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Duyệt" }));
    expect(screen.getByRole("button", { name: "Xác nhận" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Ghi chú của người duyệt"), { target: { value: "Reviewed both independent evidence families." } });
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận" }));
    await waitFor(() => expect(onDecide).toHaveBeenCalledWith(candidate, expect.objectContaining({ action: "approve", relationship: "endorsed_third_party_service", identity_type: "website" })));
  });
});
