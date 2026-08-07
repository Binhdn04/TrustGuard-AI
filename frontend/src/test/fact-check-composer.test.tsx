import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { FactCheckComposer } from "@/components/analysis/fact-check-composer";

describe("FactCheckComposer", () => {
  it("Không cho submit nội dung rỗng", () => {
    const handleSubmit = vi.fn();
    render(<FactCheckComposer onSubmit={handleSubmit} />);
    
    const submitBtn = screen.getByRole("button", { name: /phân tích/i });
    expect(submitBtn).toBeDisabled();
    
    fireEvent.click(submitBtn);
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it("Text không URL không hiển thị consent", () => {
    render(<FactCheckComposer onSubmit={vi.fn()} />);
    const textarea = screen.getByPlaceholderText(/Ví dụ:/i);
    
    fireEvent.change(textarea, { target: { value: "Một nội dung bình thường không có link" } });
    
    const consentLabel = screen.queryByText(/Kiểm tra thêm độ an toàn/i);
    expect(consentLabel).not.toBeInTheDocument();
  });

  it("Text có URL hiển thị URL panel", () => {
    render(<FactCheckComposer onSubmit={vi.fn()} />);
    const textarea = screen.getByPlaceholderText(/Ví dụ:/i);
    
    fireEvent.change(textarea, { target: { value: "Nội dung có link https://example.com" } });
    
    const consentLabel = screen.getByText(/Kiểm tra thêm độ an toàn/i);
    expect(consentLabel).toBeInTheDocument();
  });

  it("Consent được truyền đúng vào request", () => {
    const handleSubmit = vi.fn();
    render(<FactCheckComposer onSubmit={handleSubmit} />);
    
    const textarea = screen.getByPlaceholderText(/Ví dụ:/i);
    fireEvent.change(textarea, { target: { value: "Nội dung có link https://example.com" } });
    
    const checkbox = screen.getByRole("checkbox");
    fireEvent.click(checkbox);
    
    const submitBtn = screen.getByRole("button", { name: /phân tích/i });
    expect(submitBtn).not.toBeDisabled();
    fireEvent.click(submitBtn);
    
    expect(handleSubmit).toHaveBeenCalledWith("Nội dung có link https://example.com", true);
  });

  it("Xóa URL sẽ thu hồi consent trước đó", () => {
    const handleSubmit = vi.fn();
    render(<FactCheckComposer onSubmit={handleSubmit} />);

    const textarea = screen.getByPlaceholderText(/Ví dụ:/i);
    fireEvent.change(textarea, { target: { value: "Link https://example.com" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(textarea, { target: { value: "Không còn link" } });
    fireEvent.change(textarea, { target: { value: "Link mới https://example.org" } });
    fireEvent.click(screen.getByRole("button", { name: /phân tích/i }));

    expect(handleSubmit).toHaveBeenCalledWith("Link mới https://example.org", false);
  });
});
