import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LinkedMessage } from "@/components/analysis/linked-message";

describe("LinkedMessage", () => {
  it("keeps submitted HTTP links clickable without sending a referrer", () => {
    render(<LinkedMessage value="Kiểm tra https://example.test/path?q=1, giúp tôi." />);

    const link = screen.getByRole("link", { name: "https://example.test/path?q=1" });
    expect(link).toHaveAttribute("href", "https://example.test/path?q=1");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", expect.stringContaining("noopener"));
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(screen.getByText(/, giúp tôi\./)).toBeInTheDocument();
  });

  it("does not turn non-HTTP protocols into clickable links", () => {
    render(<LinkedMessage value="Không mở javascript:alert(1) hoặc ftp://example.test/file" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
