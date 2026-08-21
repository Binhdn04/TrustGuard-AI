import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SecurityChatComposer } from "@/components/analysis/security-chat-composer";

describe("SecurityChatComposer keyboard submission", () => {
  it("types and rotates through user-friendly intake examples", () => {
    vi.useFakeTimers();
    const { unmount } = render(<SecurityChatComposer onSubmit={vi.fn()} busy={false} />);
    const composer = screen.getByRole("textbox") as HTMLTextAreaElement;
    try {
      expect(composer).toHaveAttribute("placeholder", "");
      for (let step = 0; step < 15; step += 1) act(() => vi.advanceTimersByTime(50));
      const firstTypedExample = composer.placeholder;
      expect(firstTypedExample).toMatch(/^Ví dụ: Người lạ/);

      for (let step = 0; step < 175; step += 1) act(() => vi.advanceTimersByTime(50));
      expect(composer.placeholder).toMatch(/^Ví dụ: Tin nhắn/);
      expect(composer.placeholder).not.toBe(firstTypedExample);
    } finally {
      unmount();
      vi.useRealTimers();
    }
  });

  it("preserves an HTTP link from rich clipboard HTML", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox") as HTMLTextAreaElement;

    fireEvent.paste(composer, {
      clipboardData: {
        getData: (type: string) => type === "text/html"
          ? '<p>Mở <a href="https://forms.example.test/application?id=42">biểu mẫu này</a> để đăng ký</p>'
          : "Mở biểu mẫu này để đăng ký",
      },
    });

    expect(composer).toHaveValue(
      "Mở biểu mẫu này (https://forms.example.test/application?id=42) để đăng ký",
    );
    fireEvent.keyDown(composer, { key: "Enter", code: "Enter" });
    expect(onSubmit).toHaveBeenCalledWith(
      "Mở biểu mẫu này (https://forms.example.test/application?id=42) để đăng ký",
    );
  });

  it("submits a trimmed message with Enter and clears the composer", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox") as HTMLTextAreaElement;

    fireEvent.change(composer, { target: { value: "  Kiểm tra tin nhắn này  " } });
    const accepted = fireEvent.keyDown(composer, { key: "Enter", code: "Enter" });

    expect(accepted).toBe(false);
    expect(onSubmit).toHaveBeenCalledOnce();
    expect(onSubmit).toHaveBeenCalledWith("Kiểm tra tin nhắn này");
    expect(composer).toHaveValue("");
  });

  it("keeps Shift+Enter available for a line break", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.change(composer, { target: { value: "Dòng một" } });
    const accepted = fireEvent.keyDown(composer, { key: "Enter", code: "Enter", shiftKey: true });

    expect(accepted).toBe(true);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("does not submit Enter while an IME composition is active", () => {
    const onSubmit = vi.fn();
    render(<SecurityChatComposer onSubmit={onSubmit} busy={false} />);
    const composer = screen.getByRole("textbox");

    fireEvent.change(composer, { target: { value: "Đang nhập" } });
    const accepted = fireEvent.keyDown(composer, {
      key: "Enter",
      code: "Enter",
      isComposing: true,
    });

    expect(accepted).toBe(true);
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
