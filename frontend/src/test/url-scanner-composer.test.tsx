import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { UrlScannerComposer } from "@/components/analysis/url-scanner-composer";

describe("UrlScannerComposer", () => {
  it("Không cho submit nội dung rỗng", () => {
    const handleSubmit = vi.fn();
    render(<UrlScannerComposer onSubmit={handleSubmit} />);
    
    const submitBtn = screen.getByRole("button", { name: /quét link/i });
    expect(submitBtn).toBeDisabled();
    
    fireEvent.click(submitBtn);
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("Hiện lỗi nếu nhập URL không hợp lệ", () => {
    const handleSubmit = vi.fn();
    render(<UrlScannerComposer onSubmit={handleSubmit} />);
    
    const input = screen.getByRole("textbox");
    fireEvent.change(input, { target: { value: "not-a-valid-url" } });
    
    const submitBtn = screen.getByRole("button", { name: /quét link/i });
    expect(submitBtn).not.toBeDisabled();
    
    fireEvent.click(submitBtn);
    
    expect(screen.getByText(/Vui lòng nhập một địa chỉ URL hợp lệ/i)).toBeInTheDocument();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("Submit URL hợp lệ", () => {
    const handleSubmit = vi.fn();
    render(<UrlScannerComposer onSubmit={handleSubmit} />);
    
    const input = screen.getByRole("textbox");
    fireEvent.change(input, { target: { value: "https://example.com/scam" } });
    
    const submitBtn = screen.getByRole("button", { name: /quét link/i });
    fireEvent.click(submitBtn);
    
    expect(screen.queryByText(/Vui lòng nhập một địa chỉ URL hợp lệ/i)).not.toBeInTheDocument();
    expect(handleSubmit).toHaveBeenCalledWith("https://example.com/scam");
  });
});
