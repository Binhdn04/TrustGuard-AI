"use client";

import { useEffect, useState, useSyncExternalStore, type ClipboardEvent, type FormEvent, type KeyboardEvent } from "react";
import { ArrowUp, Loader2, ShieldCheck } from "lucide-react";

import {
  AUTOMATIC_LOOKUP_DISCLOSURE,
  OFFICIAL_SOURCE_LOOKUP_DISCLOSURE,
} from "@/lib/security/automatic-lookup-policy";
import { richClipboardTextWithLinks } from "@/lib/security/message-links";
import { cn } from "@/lib/utils";

interface Props {
  onSubmit(message: string): void;
  busy: boolean;
  followUp?: string | null;
  variant?: "intake" | "compact";
}

const TYPEWRITER_EXAMPLES = [
  "Người lạ gửi link và yêu cầu tôi đăng nhập, có an toàn không?",
  "Tin nhắn này yêu cầu gửi mã OTP, tôi nên làm gì?",
  "Trang tuyển dụng này có phải của công ty thật không?",
  "Họ thúc giục tôi chuyển tiền để nhận quà.",
  "Liên kết này có đáng tin không?",
] as const;

function subscribeToReducedMotion(onChange: () => void): () => void {
  if (typeof window === "undefined" || !window.matchMedia) return () => undefined;
  const media = window.matchMedia("(prefers-reduced-motion: reduce)");
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

function reducedMotionSnapshot(): boolean {
  return typeof window !== "undefined"
    && Boolean(window.matchMedia?.("(prefers-reduced-motion: reduce)").matches);
}

function useTypewriterPlaceholder(enabled: boolean): string {
  const reducedMotion = useSyncExternalStore(subscribeToReducedMotion, reducedMotionSnapshot, () => false);
  const [exampleIndex, setExampleIndex] = useState(0);
  const [characterCount, setCharacterCount] = useState(0);
  const [phase, setPhase] = useState<"typing" | "holding" | "deleting">("typing");
  const current = TYPEWRITER_EXAMPLES[exampleIndex];

  useEffect(() => {
    if (!enabled || reducedMotion) return;
    const delay = phase === "typing"
      ? 42
      : phase === "holding"
        ? 1_650
        : characterCount > 0
          ? 18
          : 240;
    const timer = window.setTimeout(() => {
      if (phase === "typing") {
        if (characterCount < current.length) setCharacterCount((count) => count + 1);
        else setPhase("holding");
        return;
      }
      if (phase === "holding") {
        setPhase("deleting");
        return;
      }
      if (characterCount > 0) {
        setCharacterCount((count) => count - 1);
        return;
      }
      setExampleIndex((index) => (index + 1) % TYPEWRITER_EXAMPLES.length);
      setPhase("typing");
    }, delay);
    return () => window.clearTimeout(timer);
  }, [characterCount, current.length, enabled, phase, reducedMotion]);

  if (!enabled) return "Nhập nội dung bạn muốn hỏi…";
  if (reducedMotion) return `Ví dụ: ${TYPEWRITER_EXAMPLES[0]}`;
  return characterCount === 0 ? "" : `Ví dụ: ${current.slice(0, characterCount)}`;
}

export function SecurityChatComposer({
  onSubmit,
  busy,
  followUp,
  variant = "intake",
}: Props) {
  const [message, setMessage] = useState("");
  const animatedPlaceholder = useTypewriterPlaceholder(variant === "intake" && !followUp);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = message.trim();
    if (!value || busy) return;
    onSubmit(value);
    setMessage("");
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    if (!message.trim() || busy) return;
    event.currentTarget.form?.requestSubmit();
  };

  const handlePaste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    const richText = richClipboardTextWithLinks(event.clipboardData.getData("text/html"));
    if (richText === null) return;
    event.preventDefault();
    const start = event.currentTarget.selectionStart ?? message.length;
    const end = event.currentTarget.selectionEnd ?? start;
    const available = Math.max(0, 5000 - (message.length - (end - start)));
    const insertion = richText.slice(0, available);
    setMessage(`${message.slice(0, start)}${insertion}${message.slice(end)}`);
  };

  return (
    <form
      onSubmit={submit}
      className={cn(
        variant === "intake" ? "space-y-4" : "space-y-3",
      )}
    >
      <div>
        <label htmlFor="security-message" className={followUp ? "text-sm font-semibold leading-6" : "sr-only"}>
          {followUp ?? "Dán tin nhắn đáng ngờ hoặc mô tả hành động người gửi yêu cầu"}
        </label>
        <div className={cn("relative", followUp && "mt-2")}>
          <textarea
            id="security-message"
            value={message}
            onChange={(event) => setMessage(event.target.value)}
            onKeyDown={handleKeyDown}
            onPaste={handlePaste}
            disabled={busy}
            maxLength={5000}
            placeholder={followUp ? "Nhập câu trả lời của bạn…" : animatedPlaceholder}
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
        <p className="flex items-start gap-1.5"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />{AUTOMATIC_LOOKUP_DISCLOSURE} {OFFICIAL_SOURCE_LOOKUP_DISCLOSURE}</p>
        <span className="shrink-0 text-right">
          <span className="font-mono">{message.length}/5000</span>
        </span>
      </div>
    </form>
  );
}
