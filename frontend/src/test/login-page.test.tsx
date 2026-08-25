import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import LoginPage from "@/app/(auth)/login/page";

const auth = vi.hoisted(() => ({ login: vi.fn() }));

vi.mock("@/lib/auth-context", () => ({
  useAuth: () => ({ login: auth.login }),
}));

vi.mock("@/lib/auth/oidc", () => ({
  createOidcAuthorizationRequest: vi.fn(),
  isOidcConfigured: () => true,
}));

describe("trang đăng nhập MVP", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    auth.login.mockReset();
  });

  it("ẩn đăng nhập demo khi thiếu một trong hai demo token", () => {
    vi.stubEnv("NEXT_PUBLIC_DEMO_USER_TOKEN", "local-user-token");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ADMIN_TOKEN", "");

    render(<LoginPage />);

    expect(screen.queryByRole("button", { name: "Quyền người dùng" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Quyền quản trị bảo mật" })).not.toBeInTheDocument();
  });

  it("giữ đăng nhập demo local khi có đủ cả hai demo token", () => {
    vi.stubEnv("NEXT_PUBLIC_DEMO_USER_TOKEN", "local-user-token");
    vi.stubEnv("NEXT_PUBLIC_DEMO_ADMIN_TOKEN", "local-admin-token");

    render(<LoginPage />);

    expect(screen.getByRole("button", { name: "Quyền người dùng" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Quyền quản trị bảo mật" })).toBeInTheDocument();
  });
});
