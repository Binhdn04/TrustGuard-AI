import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AssistantMarkdownMessage } from "@/components/analysis/assistant-markdown-message";

describe("AssistantMarkdownMessage", () => {
  it("renders emphasis and lists instead of showing Markdown markers", () => {
    const { container } = render(
      <AssistantMarkdownMessage
        value={"Có hai lý do:\n\n1. **Thiếu thông tin**: chưa rõ người gửi.\n2. *Cần thận trọng*: đừng cung cấp OTP."}
      />,
    );

    expect(screen.getByText("Thiếu thông tin").tagName).toBe("STRONG");
    expect(screen.getByText("Cần thận trọng").tagName).toBe("EM");
    expect(container.querySelector("ol")).toBeInTheDocument();
    expect(container).not.toHaveTextContent("**Thiếu thông tin**");
  });

  it("keeps numbered items in one list when Markdown contains blank lines", () => {
    const { container } = render(
      <AssistantMarkdownMessage value={"1. Mục thứ nhất\n\n2. Mục thứ hai\n\n3. Mục thứ ba"} />,
    );

    expect(container.querySelectorAll("ol")).toHaveLength(1);
    expect(container.querySelectorAll("ol > li")).toHaveLength(3);
  });

  it("keeps HTTP links clickable and never interprets raw HTML", () => {
    const { container } = render(
      <AssistantMarkdownMessage
        value={'Xem [nguồn chính thức](https://example.test/help) hoặc <script>alert("x")</script>.'}
      />,
    );

    const link = screen.getByRole("link", { name: "nguồn chính thức" });
    expect(link).toHaveAttribute("href", "https://example.test/help");
    expect(link).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(container.querySelector("script")).not.toBeInTheDocument();
    expect(container).toHaveTextContent('<script>alert("x")</script>');
  });
});
