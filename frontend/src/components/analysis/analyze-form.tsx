"use client";

import { useState, type FormEvent } from "react";

import { LockIcon, SearchIcon } from "@/components/ui/icons";
import type { AnalysisCreateRequest } from "@/types/analysis";

const MAX_LENGTH = 5_000;
const EXAMPLES = [
  "Nhận quà tại https://tapdoanx-qua.example/login",
  "https://official.example/security",
];

interface AnalyzeFormProps {
  disabled?: boolean;
  onSubmit: (request: AnalysisCreateRequest) => void | Promise<void>;
}

export function AnalyzeForm({ disabled = false, onSubmit }: AnalyzeFormProps) {
  const [message, setMessage] = useState("");
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!message.trim()) {
      setError("Hãy nhập một tin nhắn hoặc URL cần kiểm tra.");
      return;
    }
    setError(null);
    void onSubmit({ message: message.trim(), consent_to_scan_urls: consent });
  }

  return (
    <form onSubmit={submit} className="space-y-5" noValidate>
      <div>
        <div className="mb-2 flex items-end justify-between gap-4">
          <label htmlFor="analysis-message" className="text-sm font-semibold text-slate-800">
            Nội dung cần kiểm tra
          </label>
          <span className="text-xs tabular-nums text-slate-400">
            {message.length.toLocaleString("vi-VN")} / 5.000
          </span>
        </div>
        <textarea
          id="analysis-message"
          value={message}
          maxLength={MAX_LENGTH}
          disabled={disabled}
          aria-describedby={error ? "analysis-error" : "analysis-hint"}
          aria-invalid={Boolean(error)}
          onChange={(event) => {
            setMessage(event.target.value);
            if (error) setError(null);
          }}
          placeholder="Dán tin nhắn, tuyên bố hoặc URL đáng ngờ vào đây…"
          className="min-h-40 w-full resize-y rounded-2xl border border-slate-200 bg-white px-4 py-4 text-[15px] leading-6 text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 disabled:cursor-wait disabled:bg-slate-50"
        />
        {error ? (
          <p id="analysis-error" role="alert" className="mt-2 text-sm font-medium text-rose-600">
            {error}
          </p>
        ) : (
          <p id="analysis-hint" className="mt-2 text-xs leading-5 text-slate-500">
            Không nhập mật khẩu, OTP, số thẻ hoặc dữ liệu cá nhân không cần thiết.
          </p>
        )}
      </div>

      <div className="flex flex-wrap gap-2" aria-label="Nội dung mẫu">
        {EXAMPLES.map((example, index) => (
          <button
            key={example}
            type="button"
            disabled={disabled}
            onClick={() => setMessage(example)}
            className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-cyan-300 hover:bg-cyan-50 hover:text-cyan-800 disabled:opacity-50"
          >
            Mẫu {index + 1}
          </button>
        ))}
      </div>

      <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-slate-200 bg-slate-50/70 p-4 transition has-[:checked]:border-cyan-300 has-[:checked]:bg-cyan-50/50">
        <input
          type="checkbox"
          checked={consent}
          disabled={disabled}
          onChange={(event) => setConsent(event.target.checked)}
          className="mt-0.5 size-4 accent-cyan-600"
        />
        <span>
          <span className="flex items-center gap-2 text-sm font-semibold text-slate-800">
            <LockIcon className="size-4 text-cyan-700" />
            Cho phép kiểm tra URL qua dịch vụ bên ngoài
          </span>
          <span className="mt-1 block text-xs leading-5 text-slate-500">
            Chỉ URL và metadata cần thiết được gửi đi. Nếu không đồng ý, hệ thống vẫn chạy kiểm tra nội bộ và nêu rõ giới hạn.
          </span>
        </span>
      </label>

      <button
        type="submit"
        disabled={disabled}
        className="flex min-h-12 w-full items-center justify-center gap-2 rounded-xl bg-[var(--navy)] px-5 py-3 text-sm font-bold text-white shadow-lg shadow-slate-900/10 transition hover:-translate-y-0.5 hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600 disabled:cursor-wait disabled:translate-y-0 disabled:opacity-60 sm:w-auto sm:min-w-44"
      >
        <SearchIcon className="size-5" />
        {disabled ? "Đang kiểm tra…" : "Phân tích ngay"}
      </button>
    </form>
  );
}
