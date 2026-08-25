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
  admin_action_contract: "v4",
  executable_admin_actions: ["add_to_blacklist"],
  deferred_admin_actions: ["block_domain"],
};

describe("application shell", () => {
  it("keeps admin destinations out of the user navigation", () => {
    render(<WorkspaceNavigation pathname="/" role="user" capabilities={capabilities} />);

    expect(screen.getByRole("link", { name: /^Kiểm tra/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Lịch sử/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Hồ sơ/i })).not.toBeInTheDocument();
    expect(screen.queryByText("Quản trị bảo mật")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Duyệt bảo mật/i })).not.toBeInTheDocument();
  });

  it("links every implemented admin workspace", () => {
    render(<WorkspaceNavigation pathname="/admin/review" role="security_admin" capabilities={capabilities} />);

    expect(screen.getByRole("link", { name: /Duyệt bảo mật/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Duyệt bảo mật/i })).toHaveAttribute("href", "/admin/review");
    expect(screen.getByRole("link", { name: /Tin cậy & chặn/i })).toHaveAttribute("href", "/admin/trust");
    expect(screen.queryByRole("link", { name: /Observatory/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^Audit/i })).not.toBeInTheDocument();
  });

  it("provides a labeled mobile navigation", () => {
    render(<MobileNavigation pathname="/history" role="user" capabilities={capabilities} />);

    const navigation = screen.getByRole("navigation", { name: "Điều hướng di động" });
    expect(navigation).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Lịch sử/i })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("link", { name: /Hồ sơ/i })).not.toBeInTheDocument();
  });

  it("loads real capabilities and does not render a static readiness badge", async () => {
    const api = {
      getCapabilities: vi.fn().mockResolvedValue(capabilities),
    } as unknown as SecurityAnalysisApi;

    render(<AppShell api={api}><p>Workspace content</p></AppShell>);

    expect(await screen.findAllByRole("link", { name: /Duyệt bảo mật/i })).not.toHaveLength(0);
    expect(api.getCapabilities).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("official-verification-capability")).not.toBeInTheDocument();
    expect(screen.queryByText(/Hệ thống sẵn sàng/i)).not.toBeInTheDocument();
    expect(screen.getByText("Trợ lý an toàn số")).toBeInTheDocument();
    expect(screen.getByText("Workspace content")).toBeInTheDocument();
  });

  it("keeps technical web readiness out of the application header", async () => {
    const api = {
      getCapabilities: vi.fn().mockResolvedValue({
        ...capabilities,
        official_link_verification: true,
        official_web_search_ready: true,
      }),
    } as unknown as SecurityAnalysisApi;

    render(<AppShell api={api}><p>Workspace content</p></AppShell>);
    expect(await screen.findAllByRole("link", { name: /Duyệt bảo mật/i })).not.toHaveLength(0);
    expect(screen.queryByText(/Xác minh nguồn chính thức/i)).not.toBeInTheDocument();
  });

  it("keeps the two MVP admin destinations when capability loading fails", async () => {
    const api = {
      getCapabilities: vi.fn().mockRejectedValue(new Error("capabilities unavailable")),
    } as unknown as SecurityAnalysisApi;

    render(<AppShell api={api}><p>Workspace content</p></AppShell>);

    expect(await screen.findAllByRole("link", { name: /Duyệt bảo mật/i })).not.toHaveLength(0);
    expect(screen.getAllByRole("link", { name: /Tin cậy & chặn/i })).not.toHaveLength(0);
    expect(screen.queryByTestId("official-verification-capability")).not.toBeInTheDocument();
  });
});
