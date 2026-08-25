import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider, useAuth } from "@/lib/auth-context";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
const oidc = vi.hoisted(() => ({
  clearSession: vi.fn(),
  restoreSession: vi.fn().mockResolvedValue(null),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/login",
  useRouter: () => ({ replace: navigation.replace }),
}));

vi.mock("@/lib/auth/oidc", () => ({
  clearOidcSession: oidc.clearSession,
  getOidcLogoutUrl: () => null,
  loadOidcSession: () => null,
  oidcRefreshDelay: () => 60_000,
  refreshOidcSession: vi.fn(),
  restoreOidcSession: oidc.restoreSession,
  saveOidcSession: vi.fn(),
}));

function AuthActions() {
  const { isLoading, login, logout } = useAuth();
  if (isLoading) return <p>Đang tải</p>;
  return (
    <>
      <button type="button" onClick={() => login({ id: "u-1", name: "Local User", email: "user@example.test", role: "user" })}>
        Đăng nhập local
      </button>
      <button type="button" onClick={logout}>Đăng xuất</button>
    </>
  );
}

describe("AuthProvider local", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    navigation.replace.mockReset();
    oidc.clearSession.mockReset();
    oidc.restoreSession.mockReset().mockResolvedValue(null);
  });

  it("tách demo local khỏi OIDC và xóa demo session khi logout", async () => {
    render(<AuthProvider><AuthActions /></AuthProvider>);

    fireEvent.click(await screen.findByRole("button", { name: "Đăng nhập local" }));
    expect(oidc.clearSession).toHaveBeenCalledOnce();
    expect(JSON.parse(window.localStorage.getItem("ai_protect_user") ?? "{}")).toMatchObject({ id: "u-1", role: "user" });

    fireEvent.click(screen.getByRole("button", { name: "Đăng xuất" }));

    await waitFor(() => expect(window.localStorage.getItem("ai_protect_user")).toBeNull());
    expect(oidc.clearSession).toHaveBeenCalledTimes(2);
    expect(navigation.replace).toHaveBeenCalledWith("/login");
  });
});
