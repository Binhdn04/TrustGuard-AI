"use client";

import { useState, type FormEvent } from "react";
import { ArrowUp, Loader2, ShieldCheck } from "lucide-react";

import { AUTOMATIC_LOOKUP_DISCLOSURE } from "@/lib/security/automatic-lookup-policy";
import { cn } from "@/lib/utils";

interface Props {
  onSubmit(message: string): void;
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

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = message.trim();
    if (!value || busy) return;
    onSubmit(value);
    setMessage("");
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
            onChange={(event) => setMessage(event.target.value)}
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

      <div className="flex items-start justify-between gap-4 text-[11px] leading-5 text-muted-foreground">
        <p className="flex items-start gap-1.5"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />{AUTOMATIC_LOOKUP_DISCLOSURE}</p>
        <span className="shrink-0 font-mono">{message.length}/5000</span>
      </div>
    </form>
  );
}
