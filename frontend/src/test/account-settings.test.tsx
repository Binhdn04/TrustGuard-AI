import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AccountSettings } from "@/components/account/account-settings";
import { UserMenu } from "@/components/layout/user-menu";
import { AccountPreferencesProvider } from "@/lib/account-preferences-context";

const auth = vi.hoisted(() => ({
  user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: "security_admin" as const },
  logout: vi.fn(),
}));
const theme = vi.hoisted(() => ({ current: "system", resolved: "light", setTheme: vi.fn() }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ user: auth.user, isLoading: false, logout: auth.logout }),
}));
vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: theme.current, resolvedTheme: theme.resolved, setTheme: theme.setTheme }),
}));

function renderWithPreferences(node: React.ReactNode) {
  return render(<AccountPreferencesProvider>{node}</AccountPreferencesProvider>);
}

describe("account MVP", () => {
  beforeEach(() => {
    window.localStorage.clear();
    auth.logout.mockReset();
    theme.setTheme.mockReset();
    document.documentElement.removeAttribute("data-motion");
  });

  it("opens a focused avatar menu with profile, settings, admin and logout actions", async () => {
    renderWithPreferences(<UserMenu />);

    fireEvent.click(screen.getByRole("button", { name: "Mở menu tài khoản" }));

    expect(screen.getByRole("menu", { name: "Tài khoản" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Hồ sơ cá nhân" })).toHaveAttribute("href", "/profile");
    expect(screen.getByRole("menuitem", { name: "Cài đặt" })).toHaveAttribute("href", "/settings");
    expect(screen.queryByRole("menuitem", { name: "Lịch sử & báo cáo" })).not.toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Khu vực quản trị" })).toHaveAttribute("href", "/admin");

    fireEvent.click(screen.getByRole("menuitem", { name: "Đăng xuất" }));
    expect(auth.logout).toHaveBeenCalledOnce();
  });

  it("saves only device-local display preferences for the current user", async () => {
    renderWithPreferences(<AccountSettings section="profile" />);

    fireEvent.change(screen.getByRole("textbox", { name: "Tên hiển thị" }), { target: { value: "Security Reviewer" } });
    fireEvent.click(screen.getByRole("radio", { name: "violet" }));
    fireEvent.click(screen.getByRole("button", { name: "Lưu hồ sơ" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Đã lưu");
    await waitFor(() => {
      const stored = window.localStorage.getItem("trustguard_account_preferences_v1:admin-1");
      expect(stored).not.toBeNull();
      expect(JSON.parse(stored ?? "{}")).toEqual(expect.objectContaining({
        displayName: "Security Reviewer",
        avatarTone: "violet",
      }));
    });
  });

  it("groups device preferences and privacy information under settings", async () => {
    renderWithPreferences(<AccountSettings section="settings" />);

    fireEvent.change(screen.getByRole("combobox", { name: "Giao diện" }), { target: { value: "dark" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Mức chi tiết mặc định" }), { target: { value: "analyst" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Hiệu ứng chuyển động" }), { target: { value: "reduced" } });

    expect(theme.setTheme).toHaveBeenCalledWith("dark");
    await waitFor(() => expect(document.documentElement.dataset.motion).toBe("reduced"));
    expect(screen.queryByRole("option", { name: "Theo hệ thống" })).not.toBeInTheDocument();

    expect(screen.getByText(/luôn được hỏi theo từng yêu cầu/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Đăng xuất" })).not.toBeInTheDocument();
  });
});
