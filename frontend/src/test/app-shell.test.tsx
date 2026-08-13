import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AppShell } from "@/components/layout/app-shell";
import { MobileNavigation } from "@/components/layout/mobile-navigation";
import { WorkspaceNavigation } from "@/components/layout/workspace-navigation";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type { SecurityCapabilitiesResponseV4 } from "@/types/generated/api-v4";

vi.mock("next/navigation", () => ({ usePathname: () => "/" }));
vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({
    user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: "security_admin" },
    isLoading: false,
    logout: vi.fn(),
  }),
}));

const capabilities: SecurityCapabilitiesResponseV4 = {
  contract_version: "v4",
  product_profile: "security_triage_vnext",
  release_profile: "pre_cutover",
  conversation_resume: true,
  admin_feedback_review: true,
  intelligence_explorer: true,
  unified_v4_audit: true,
  admin_action_contract: "v3",
  executable_admin_actions: ["add_to_blacklist"],
  deferred_admin_actions: ["block_domain"],
  compatibility_contracts: ["v2", "v3", "v4"],
};

describe("application shell", () => {
  it("keeps admin destinations out of the user navigation", () => {
    render(<WorkspaceNavigation pathname="/" role="user" capabilities={capabilities} />);

    expect(screen.getByRole("link", { name: /New case/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Cases/i })).toBeInTheDocument();
    expect(screen.queryByText("Admin")).not.toBeInTheDocument();
    expect(screen.queryByText("Review")).not.toBeInTheDocument();
  });

  it("links every implemented admin workspace", () => {
    render(<WorkspaceNavigation pathname="/admin/review" role="security_admin" capabilities={capabilities} />);

    expect(screen.getByRole("link", { name: /Observatory/i })).toHaveAttribute("href", "/admin/observatory");
    expect(screen.getByRole("link", { name: /Review/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Review/i })).toHaveAttribute("href", "/admin/review");
    expect(screen.getByRole("link", { name: /Trust/i })).toHaveAttribute("href", "/admin/trust");
    expect(screen.getByRole("link", { name: /Audit/i })).toHaveAttribute("href", "/admin/audit");
    expect(screen.getByRole("link", { name: /Compatibility/i })).toHaveAttribute("href", "/admin/compatibility");
  });

  it("provides a labeled mobile navigation", () => {
    render(<MobileNavigation pathname="/history" role="user" capabilities={capabilities} />);

    const navigation = screen.getByRole("navigation", { name: "Điều hướng di động" });
    expect(navigation).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Cases" })).toHaveAttribute("aria-current", "page");
  });

  it("loads real capabilities and does not render a static readiness badge", async () => {
    const api = {
      getCapabilities: vi.fn().mockResolvedValue(capabilities),
    } as unknown as SecurityAnalysisApi;

    render(<AppShell api={api}><p>Workspace content</p></AppShell>);

    expect(await screen.findAllByText("Observatory")).not.toHaveLength(0);
    expect(api.getCapabilities).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/Hệ thống sẵn sàng/i)).not.toBeInTheDocument();
    expect(screen.getByText("Workspace content")).toBeInTheDocument();
  });
});
