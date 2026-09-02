"use client";

import { useEffect, useRef, useState, useSyncExternalStore, type ClipboardEvent, type FormEvent, type KeyboardEvent, type MouseEvent } from "react";
import { ArrowUp, Loader2, ShieldCheck } from "lucide-react";

import {
  AUTOMATIC_LOOKUP_DISCLOSURE,
} from "@/lib/security/automatic-lookup-policy";
import {
  messageTextParts,
  richClipboardMessageParts,
  richClipboardTextWithLinks,
  safeHttpHref,
  type MessageTextPart,
} from "@/lib/security/message-links";
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

function serializeEditableNode(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? "";
  if (!(node instanceof HTMLElement)) return "";
  if (node.tagName === "BR") return "\n";

  const content = Array.from(node.childNodes).map(serializeEditableNode).join("");
  if (node.tagName === "A") {
    const href = safeHttpHref(node.getAttribute("href") ?? "");
    if (!href) return content;
    const label = content.trim();
    return !label || label.includes(href) ? (label || href) : `${label} (${href})`;
  }
  return node.tagName === "DIV" || node.tagName === "P" ? `${content}\n` : content;
}

function textFromEditable(element: HTMLElement): string {
  return Array.from(element.childNodes).map(serializeEditableNode).join("");
}

function messageFragmentFromParts(parts: MessageTextPart[]): DocumentFragment {
  const fragment = document.createDocumentFragment();
  for (const part of parts) {
    if (!part.href) {
      fragment.append(document.createTextNode(part.text));
      continue;
    }
    const link = document.createElement("a");
    link.href = part.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer nofollow";
    link.referrerPolicy = "no-referrer";
    link.className = "break-all font-medium underline decoration-current/50 underline-offset-2 hover:decoration-current";
    link.title = "Mở liên kết trong tab mới; liên kết chưa được xác nhận an toàn";
    link.textContent = part.text;
    fragment.append(link);
  }
  return fragment;
}

function messageFragment(value: string): DocumentFragment {
  return messageFragmentFromParts(messageTextParts(value));
}

function insertFragmentAtSelection(element: HTMLElement, fragment: DocumentFragment): void {
  const selection = window.getSelection();
  const range = selection?.rangeCount ? selection.getRangeAt(0) : null;
  if (!range || !element.contains(range.commonAncestorContainer)) {
    element.append(fragment);
    return;
  }

  range.deleteContents();
  const lastNode = fragment.lastChild;
  range.insertNode(fragment);
  if (!lastNode || !selection) return;
  range.setStartAfter(lastNode);
  range.collapse(true);
  selection.removeAllRanges();
  selection.addRange(range);
}

export function SecurityChatComposer({
  onSubmit,
  busy,
  followUp,
  variant = "intake",
}: Props) {
  const [message, setMessage] = useState("");
  const editorRef = useRef<HTMLDivElement>(null);
  const animatedPlaceholder = useTypewriterPlaceholder(variant === "intake" && !followUp);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = (editorRef.current ? textFromEditable(editorRef.current) : message).trim();
    if (!value || busy) return;
    onSubmit(value);
    // Clear synchronously with this submission. A passive effect that clears
    // an empty, newly mounted follow-up composer can otherwise race with the
    // user's next input and drop that turn.
    editorRef.current?.replaceChildren();
    setMessage("");
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    if (!textFromEditable(event.currentTarget).trim() || busy) return;
    event.currentTarget.closest("form")?.requestSubmit();
  };

  const handleInput = (event: FormEvent<HTMLDivElement>) => {
    const rawValue = textFromEditable(event.currentTarget);
    const value = rawValue.slice(0, 5000);
    if (value !== rawValue) event.currentTarget.textContent = value;
    setMessage(value);
  };

  const handlePaste = (event: ClipboardEvent<HTMLDivElement>) => {
    const clipboardHtml = event.clipboardData.getData("text/html");
    const richText = richClipboardTextWithLinks(clipboardHtml);
    const richParts = richClipboardMessageParts(clipboardHtml);
    const clipboardText = richText ?? event.clipboardData.getData("text/plain");
    if (!clipboardText) return;
    event.preventDefault();
    const selection = window.getSelection();
    const selectedLength = selection?.rangeCount ? selection.getRangeAt(0).toString().length : 0;
    const available = Math.max(0, 5000 - (message.length - selectedLength));
    const insertion = clipboardText.slice(0, available);
    const fragment = richParts && insertion === clipboardText
      ? messageFragmentFromParts(richParts)
      : messageFragment(insertion);
    insertFragmentAtSelection(event.currentTarget, fragment);
    setMessage(textFromEditable(event.currentTarget));
  };

  const handleLinkClick = (event: MouseEvent<HTMLDivElement>) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const link = target.closest<HTMLAnchorElement>("a[href]");
    if (!link || !event.currentTarget.contains(link)) return;
    event.preventDefault();
    window.open(link.href, "_blank", "noopener,noreferrer");
  };

  return (
    <form
      onSubmit={submit}
      className={cn(
        variant === "intake" ? "space-y-4" : "space-y-3",
      )}
    >
      <div>
        <label id="security-message-label" htmlFor="security-message" className={followUp ? "text-sm font-semibold leading-6" : "sr-only"}>
          {followUp ?? "Dán tin nhắn đáng ngờ hoặc mô tả hành động người gửi yêu cầu"}
        </label>
        <div className={cn("relative", followUp && "mt-2")}>
          <div
            ref={editorRef}
            id="security-message"
            role="textbox"
            aria-labelledby="security-message-label"
            aria-multiline="true"
            contentEditable={!busy}
            suppressContentEditableWarning
            onKeyDown={handleKeyDown}
            onInput={handleInput}
            onPaste={handlePaste}
            onClick={handleLinkClick}
            data-placeholder={followUp ? "Nhập câu trả lời của bạn…" : animatedPlaceholder}
            className={cn(
              "w-full resize-y overflow-auto whitespace-pre-wrap break-words rounded-xl border border-input bg-background/75 px-4 py-3 pr-14 text-sm leading-6 outline-none transition-shadow focus:border-primary focus:ring-2 focus:ring-primary/15 empty:before:pointer-events-none empty:before:text-muted-foreground empty:before:content-[attr(data-placeholder)] disabled:opacity-60",
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
        <span className="shrink-0 text-right">
          <span className="font-mono">{message.length}/5000</span>
        </span>
      </div>
    </form>
  );
}
