import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AccountSettings } from "@/components/account/account-settings";
import { UserMenu } from "@/components/layout/user-menu";
import { AccountPreferencesProvider } from "@/lib/account-preferences-context";

const auth = vi.hoisted(() => ({
  user: { id: "admin-1", name: "Admin", email: "admin@example.test", role: "security_admin" as const },
  logout: vi.fn(),
}));
const theme = vi.hoisted(() => ({ current: "system", setTheme: vi.fn() }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ user: auth.user, isLoading: false, logout: auth.logout }),
}));
vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: theme.current, setTheme: theme.setTheme }),
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

  it("opens a functional avatar menu with account, history, admin and logout actions", async () => {
    renderWithPreferences(<UserMenu />);

    fireEvent.click(screen.getByRole("button", { name: "Mở menu tài khoản" }));

    expect(screen.getByRole("menu", { name: "Tài khoản" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Hồ sơ cá nhân" })).toHaveAttribute("href", "/profile?tab=profile");
    expect(screen.getByRole("menuitem", { name: "Cài đặt" })).toHaveAttribute("href", "/profile?tab=preferences");
    expect(screen.getByRole("menuitem", { name: "Lịch sử & báo cáo" })).toHaveAttribute("href", "/history");
    expect(screen.getByRole("menuitem", { name: "Admin Dashboard" })).toHaveAttribute("href", "/admin");

    fireEvent.click(screen.getByRole("menuitem", { name: "Đăng xuất" }));
    expect(auth.logout).toHaveBeenCalledOnce();
  });

  it("saves only device-local display preferences for the current user", async () => {
    renderWithPreferences(<AccountSettings initialTab="profile" />);

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

  it("keeps consent request-scoped while applying presentation preferences", async () => {
    renderWithPreferences(<AccountSettings initialTab="preferences" />);

    fireEvent.change(screen.getByRole("combobox", { name: "Giao diện" }), { target: { value: "dark" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Mức chi tiết mặc định" }), { target: { value: "analyst" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Chuyển động" }), { target: { value: "reduced" } });

    expect(theme.setTheme).toHaveBeenCalledWith("dark");
    await waitFor(() => expect(document.documentElement.dataset.motion).toBe("reduced"));

    fireEvent.click(screen.getByRole("button", { name: "Quyền riêng tư" }));
    expect(screen.getByText(/luôn được hỏi theo từng request/i)).toBeInTheDocument();
  });
});
