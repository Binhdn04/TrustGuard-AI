import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SecurityChatComposer } from "@/components/analysis/security-chat-composer";

describe("SecurityChatComposer keyboard submission", () => {
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
