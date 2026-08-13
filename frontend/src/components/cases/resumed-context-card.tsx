"use client";

import { useMemo, useState, type FormEvent } from "react";
import { ArrowUp, History, Loader2, ShieldCheck } from "lucide-react";

import type { SecurityConversationV4 } from "@/types/generated/api-v4";

export function ResumedContextCard({
  conversation,
  busy,
  issue,
  onResume,
}: {
  conversation: SecurityConversationV4;
  busy: boolean;
  issue: string | null;
  onResume(message: string, externalLookup: boolean, officialLookup: boolean): Promise<boolean>;
}) {
  const [message, setMessage] = useState("");
  const [externalLookup, setExternalLookup] = useState(false);
  const [officialLookup, setOfficialLookup] = useState(false);
  const context = conversation.summary.security_context;
  const hasUrl = useMemo(() => /https?:\/\/[^\s]+/iu.test(message), [message]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const value = message.trim();
    if (!value || busy || conversation.status !== "active") return;
    const accepted = await onResume(value, hasUrl && externalLookup, officialLookup);
    if (accepted) {
      setMessage("");
      setExternalLookup(false);
      setOfficialLookup(false);
    }
  };

  const retainedSignals = context ? [
    context.credential_request && "credential request",
    context.otp_request && "OTP request",
    context.payment_request && "payment request",
    context.personal_information_request && "personal information request",
    context.urgency && "urgency",
  ].filter(Boolean) as string[] : [];

  return (
    <section aria-labelledby="retained-context-heading" className="case-panel overflow-hidden">
      <header className="border-b border-border/70 px-5 py-4">
        <p className="micro-label text-primary">PRIVACY-SAFE RESUME</p>
        <h2 id="retained-context-heading" className="mt-1 flex items-center gap-2 text-base font-semibold"><History className="size-4" />Structured context retained</h2>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">Không dựng lại raw user/assistant transcript. Chỉ dùng summary mà conversation API trả về.</p>
      </header>

      <div className="space-y-4 p-5">
        <dl className="grid gap-3 text-xs sm:grid-cols-2">
          <div><dt className="text-muted-foreground">Scenario</dt><dd className="mt-0.5 font-mono font-semibold">{context?.scenario ?? "—"}</dd></div>
          <div><dt className="text-muted-foreground">Potential threat</dt><dd className="mt-0.5 font-mono font-semibold">{context?.potential_threat ?? "—"}</dd></div>
          <div><dt className="text-muted-foreground">Claimed entity</dt><dd className="mt-0.5 font-semibold">{context?.claimed_entity ?? "—"}</dd></div>
          <div><dt className="text-muted-foreground">Requested action</dt><dd className="mt-0.5 font-mono font-semibold">{context?.requested_action ?? "—"}</dd></div>
        </dl>
        {context?.urls.length ? (
          <div><p className="text-xs text-muted-foreground">Retained URLs</p><ul className="mt-1 space-y-1">{context.urls.map((url) => <li key={url} className="break-all font-mono text-[11px]">{url}</li>)}</ul></div>
        ) : null}
        {retainedSignals.length > 0 && <ul aria-label="Retained signals" className="flex flex-wrap gap-2">{retainedSignals.map((signal) => <li key={signal} className="rounded-full border border-border bg-muted px-2.5 py-1 text-[10px] font-semibold">{signal}</li>)}</ul>}
        <p className="border-t border-border/70 pt-3 font-mono text-[10px] text-muted-foreground">
          Context v{conversation.context_version} · {conversation.summary.evidence_refs.length} retained evidence refs · expires <time dateTime={conversation.expires_at}>{new Date(conversation.expires_at).toLocaleString("vi-VN")}</time>
        </p>

        {issue && <div role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs leading-5 text-amber-900 dark:text-amber-200">{issue}</div>}

        <form onSubmit={(event) => void submit(event)} className="space-y-3 border-t border-border/70 pt-4">
          <label htmlFor="resume-message" className="text-sm font-semibold">Tiếp tục case với thông tin mới</label>
          <div className="relative mt-2">
            <textarea
              id="resume-message"
              value={message}
              onChange={(event) => {
                setMessage(event.target.value);
                if (!/https?:\/\/[^\s]+/iu.test(event.target.value)) setExternalLookup(false);
              }}
              disabled={busy || conversation.status !== "active"}
              maxLength={5000}
              className="min-h-24 w-full resize-y rounded-xl border border-input bg-background px-3 py-2.5 pr-12 text-sm leading-6"
              placeholder="Bổ sung URL, yêu cầu hoặc tín hiệu mới…"
            />
            <button type="submit" disabled={!message.trim() || busy || conversation.status !== "active"} aria-label="Gửi follow-up cho case" className="absolute bottom-3 right-3 grid size-9 place-items-center rounded-lg bg-primary text-primary-foreground disabled:opacity-40">
              {busy ? <Loader2 className="size-4 animate-spin" /> : <ArrowUp className="size-4" />}
            </button>
          </div>
          {hasUrl && <label className="flex items-start gap-2 text-xs leading-5"><input type="checkbox" checked={externalLookup} onChange={(event) => setExternalLookup(event.target.checked)} className="mt-0.5 size-4 accent-[var(--primary)]" /><span><strong className="block">Cho phép kiểm tra URL bên ngoài</strong><span className="text-muted-foreground">Consent chỉ áp dụng cho follow-up này.</span></span></label>}
          <label className="flex items-start gap-2 text-xs leading-5"><input type="checkbox" checked={officialLookup} onChange={(event) => setOfficialLookup(event.target.checked)} className="mt-0.5 size-4 accent-[var(--primary)]" /><span><strong className="block">Cho phép đối chiếu nguồn chính thức</strong><span className="text-muted-foreground">Không kế thừa consent từ lượt trước.</span></span></label>
          <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />Follow-up gửi kèm conversation ID và version hiện tại; không gửi raw transcript cũ.</p>
        </form>
      </div>
    </section>
  );
}
