"use client";

import { useMemo, useState, type FormEvent } from "react";
import { Loader2, Send, ShieldCheck } from "lucide-react";

interface Props {
  onSubmit(message: string, externalLookup: boolean, officialLookup: boolean): void;
  busy: boolean;
  followUp?: string | null;
}

export function SecurityChatComposer({ onSubmit, busy, followUp }: Props) {
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
    <form onSubmit={submit} className="rounded-2xl border border-border bg-card p-4 shadow-sm sm:p-5">
      <label htmlFor="security-message" className="text-sm font-semibold">
        {followUp ?? "Dán tin nhắn đáng ngờ hoặc mô tả hành động người gửi yêu cầu"}
      </label>
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
        className="mt-3 min-h-28 w-full resize-y rounded-xl border border-border bg-background px-4 py-3 text-sm outline-none focus:border-primary focus:ring-2 focus:ring-primary/20 disabled:opacity-60"
      />
      <div className="mt-3 space-y-2">
        {hasUrl && (
          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border p-3 text-sm">
            <input type="checkbox" checked={externalLookup} onChange={(event) => setExternalLookup(event.target.checked)} className="mt-1 size-4" />
            <span><strong className="block">Cho phép kiểm tra URL bên ngoài</strong><span className="text-xs text-muted-foreground">URL/domain có thể được gửi đến provider bảo mật. Consent chỉ áp dụng cho lượt này.</span></span>
          </label>
        )}
        <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-border p-3 text-sm">
          <input type="checkbox" checked={officialLookup} onChange={(event) => setOfficialLookup(event.target.checked)} className="mt-1 size-4" />
          <span><strong className="block">Cho phép đối chiếu nguồn chính thức</strong><span className="text-xs text-muted-foreground">Chỉ dùng để xác minh chương trình, thông báo hoặc kênh chính thức được nhắc đến.</span></span>
        </label>
      </div>
      <div className="mt-4 flex items-center justify-between gap-4">
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><ShieldCheck className="size-4" />Không gửi mật khẩu, mã OTP hoặc token thật.</p>
        <button type="submit" disabled={!message.trim() || busy} className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50">
          {busy ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
          {busy ? "Đang đánh giá…" : "Gửi để đánh giá"}
        </button>
      </div>
    </form>
  );
}
