"use client";

import { useMemo, useState, type FormEvent } from "react";
import { ArrowUp, Loader2, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

interface Props {
  onSubmit(message: string, externalLookup: boolean, officialLookup: boolean): void;
  busy: boolean;
  followUp?: string | null;
  variant?: "intake" | "compact";
}

export function SecurityChatComposer({
  onSubmit,
  busy,
  followUp,
  variant = "intake",
}: Props) {
  const [message, setMessage] = useState("");
  const [externalLookup, setExternalLookup] = useState(false);
  const [officialLookup, setOfficialLookup] = useState(false);
  const hasUrl = useMemo(() => /https?:\/\/[^\s]+/iu.test(message), [message]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = message.trim();
    if (!value || busy) return;
    onSubmit(value, hasUrl && externalLookup, officialLookup);
    setMessage("");
    setExternalLookup(false);
    setOfficialLookup(false);
  };

  return (
    <form
      onSubmit={submit}
      className={cn(
        variant === "intake" ? "space-y-4" : "space-y-3",
      )}
    >
      <div>
        <label htmlFor="security-message" className="text-sm font-semibold leading-6">
          {followUp ?? "Dán tin nhắn đáng ngờ hoặc mô tả hành động người gửi yêu cầu"}
        </label>
        <div className="relative mt-2">
          <textarea
            id="security-message"
            value={message}
            onChange={(event) => {
              setMessage(event.target.value);
              if (!/https?:\/\/[^\s]+/iu.test(event.target.value)) setExternalLookup(false);
            }}
            disabled={busy}
            maxLength={5000}
            placeholder="Ví dụ: Người tự xưng là ngân hàng yêu cầu tôi mở link và gửi OTP…"
            className={cn(
              "w-full resize-y rounded-xl border border-input bg-background/75 px-4 py-3 pr-14 text-sm leading-6 outline-none transition-shadow focus:border-primary focus:ring-2 focus:ring-primary/15 disabled:opacity-60",
              variant === "intake" ? "min-h-36" : "min-h-24",
            )}
          />
          <button
            type="submit"
            disabled={!message.trim() || busy}
            aria-label={busy ? "Đang đánh giá" : "Gửi để đánh giá"}
            className="absolute bottom-3 right-3 grid size-9 place-items-center rounded-lg bg-primary text-primary-foreground shadow-sm transition-transform hover:-translate-y-0.5 disabled:translate-y-0 disabled:opacity-40"
          >
            {busy ? <Loader2 className="size-4 animate-spin" /> : <ArrowUp className="size-4" />}
          </button>
        </div>
      </div>

      <div className="space-y-2">
        {hasUrl && (
          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border/80 bg-background/45 p-3 text-xs leading-5">
            <input type="checkbox" checked={externalLookup} onChange={(event) => setExternalLookup(event.target.checked)} className="mt-0.5 size-4 accent-[var(--primary)]" />
            <span><strong className="block text-foreground">Cho phép kiểm tra URL bên ngoài</strong><span className="text-muted-foreground">URL/domain có thể được gửi đến provider bảo mật. Consent chỉ áp dụng cho lượt này.</span></span>
          </label>
        )}
        <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border/80 bg-background/45 p-3 text-xs leading-5">
          <input type="checkbox" checked={officialLookup} onChange={(event) => setOfficialLookup(event.target.checked)} className="mt-0.5 size-4 accent-[var(--primary)]" />
          <span><strong className="block text-foreground">Cho phép đối chiếu nguồn chính thức</strong><span className="text-muted-foreground">Chỉ dùng để xác minh chương trình, thông báo hoặc kênh chính thức được nhắc đến.</span></span>
        </label>
      </div>

      <div className="flex items-start justify-between gap-4 text-[11px] leading-5 text-muted-foreground">
        <p className="flex items-start gap-1.5"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />Không gửi mật khẩu, mã OTP hoặc token thật.</p>
        <span className="shrink-0 font-mono">{message.length}/5000</span>
      </div>
    </form>
  );
}
