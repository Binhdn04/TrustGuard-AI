import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SecurityChatComposer } from "@/components/analysis/security-chat-composer";

describe("SecurityChatComposer keyboard submission", () => {
  it("types and rotates through user-friendly intake examples", () => {
    vi.useFakeTimers();
    const { unmount } = render(<SecurityChatComposer onSubmit={vi.fn()} busy={false} />);
    const composer = screen.getByRole("textbox");
    try {
      expect(composer).toHaveAttribute("data-placeholder", "");
      for (let step = 0; step < 15; step += 1) act(() => vi.advanceTimersByTime(50));
      const firstTypedExample = composer.getAttribute("data-placeholder") ?? "";
      expect(firstTypedExample).toMatch(/^Ví dụ: Người lạ/);

      for (let step = 0; step < 175; step += 1) act(() => vi.advanceTimersByTime(50));
      expect(composer).toHaveAttribute("data-placeholder", expect.stringMatching(/^Ví dụ: Tin nhắn/));
      expect(composer.getAttribute("data-placeholder")).not.toBe(firstTypedExample);
    } finally {
      unmount();
      vi.useRealTimers();
    }
  });

  it("preserves an HTTP link from rich clipboard HTML", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.paste(composer, {
      clipboardData: {
        getData: (type: string) => type === "text/html"
          ? '<p>Mở <a href="https://forms.example.test/application?id=42">biểu mẫu này</a> để đăng ký</p>'
          : "Mở biểu mẫu này để đăng ký",
      },
    });

    expect(composer).toHaveTextContent("Mở biểu mẫu này để đăng ký");
    const composerLink = screen.getByRole("link", { name: "biểu mẫu này" });
    expect(composer).toContainElement(composerLink);
    expect(composerLink).toHaveAttribute("href", "https://forms.example.test/application?id=42");
    expect(composerLink).toHaveAttribute("target", "_blank");
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    fireEvent.click(composerLink);
    expect(open).toHaveBeenCalledWith("https://forms.example.test/application?id=42", "_blank", "noopener,noreferrer");
    open.mockRestore();
    fireEvent.keyDown(composer, { key: "Enter", code: "Enter" });
    expect(onSubmit).toHaveBeenCalledWith(
      "Mở biểu mẫu này (https://forms.example.test/application?id=42) để đăng ký",
    );
  });

  it("keeps a rich clipboard link label clickable while submitting its destination", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.paste(composer, {
      clipboardData: {
        getData: (type: string) => type === "text/html"
          ? '<p>Nhận quà <a href="https://rewards.example.test/claim">tại đây</a></p>'
          : "Nhận quà tại đây",
      },
    });

    const composerLink = screen.getByRole("link", { name: "tại đây" });
    expect(composer).toContainElement(composerLink);
    expect(composerLink).toHaveAttribute("href", "https://rewards.example.test/claim");
    fireEvent.keyDown(composer, { key: "Enter", code: "Enter" });
    expect(onSubmit).toHaveBeenCalledWith("Nhận quà tại đây (https://rewards.example.test/claim)");
  });

  it("submits a trimmed message with Enter and clears the composer", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.input(composer, { target: { textContent: "  Kiểm tra tin nhắn này  " } });
    const accepted = fireEvent.keyDown(composer, { key: "Enter", code: "Enter" });

    expect(accepted).toBe(false);
    expect(onSubmit).toHaveBeenCalledOnce();
    expect(onSubmit).toHaveBeenCalledWith("Kiểm tra tin nhắn này");
    expect(composer).toHaveTextContent("");
  });

  it("keeps Shift+Enter available for a line break", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.input(composer, { target: { textContent: "Dòng một" } });
    const accepted = fireEvent.keyDown(composer, { key: "Enter", code: "Enter", shiftKey: true });

    expect(accepted).toBe(true);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("does not submit Enter while an IME composition is active", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.input(composer, { target: { textContent: "Đang nhập" } });
    const accepted = fireEvent.keyDown(composer, {
      key: "Enter",
      code: "Enter",
      isComposing: true,
    });

    expect(accepted).toBe(true);
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
