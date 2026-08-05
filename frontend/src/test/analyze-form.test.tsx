import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AnalyzeForm } from "@/components/analysis/analyze-form";

describe("AnalyzeForm", () => {
  it("rejects an empty message before calling the API", () => {
    const onSubmit = vi.fn();
    render(<AnalyzeForm onSubmit={onSubmit} />);

    fireEvent.click(screen.getByRole("button", { name: "Phân tích ngay" }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Hãy nhập một tin nhắn hoặc URL cần kiểm tra.",
    );
  });

  it("submits the consent decision explicitly", () => {
    const onSubmit = vi.fn();
    render(<AnalyzeForm onSubmit={onSubmit} />);

    fireEvent.change(screen.getByLabelText("Nội dung cần kiểm tra"), {
      target: { value: "https://unknown.example/login" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /Cho phép kiểm tra URL qua dịch vụ bên ngoài/i,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Phân tích ngay" }));

    expect(onSubmit).toHaveBeenCalledWith({
      message: "https://unknown.example/login",
      consent_to_scan_urls: true,
    });
  });
});
