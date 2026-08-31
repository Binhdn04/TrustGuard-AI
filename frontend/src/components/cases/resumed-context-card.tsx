"use client";

import { useState, type FormEvent } from "react";
import { ArrowUp, History, Loader2, ShieldCheck } from "lucide-react";

import {
  AUTOMATIC_LOOKUP_DISCLOSURE,
} from "@/lib/security/automatic-lookup-policy";
import type { SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { securityLabel } from "@/lib/presentation/security-labels";
import type { SecurityConversationV4 } from "@/types/generated/api-v4";

export function ResumedContextCard({
  conversation,
  busy,
  issue,
  mode,
  onResume,
}: {
  conversation: SecurityConversationV4;
  busy: boolean;
  issue: string | null;
  mode: SecurityPresentationMode;
  onResume(message: string): Promise<boolean>;
}) {
  const [message, setMessage] = useState("");
  const context = conversation.summary.security_context;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const value = message.trim();
    if (!value || busy || conversation.status !== "active") return;
    const accepted = await onResume(value);
    if (accepted) {
      setMessage("");
    }
  };

  const retainedSignals = context ? [
    context.credential_request && "Yêu cầu thông tin đăng nhập",
    context.otp_request && "Yêu cầu mã OTP",
    context.payment_request && "Yêu cầu thanh toán",
    context.personal_information_request && "Yêu cầu thông tin cá nhân",
    context.urgency && "Thúc giục khẩn cấp",
  ].filter(Boolean) as string[] : [];

  return (
    <section aria-labelledby="retained-context-heading" className="case-panel overflow-hidden">
      <header className="border-b border-border/70 px-5 py-4">
        {mode === "analyst" && <p className="micro-label text-primary">TIẾP TỤC AN TOÀN VỀ RIÊNG TƯ</p>}
        <h2 id="retained-context-heading" className={mode === "simple" ? "flex items-center gap-2 text-base font-semibold" : "mt-1 flex items-center gap-2 text-base font-semibold"}>
          <History className="size-4" />{mode === "simple" ? "Tiếp tục cuộc trò chuyện" : "Ngữ cảnh có cấu trúc được giữ lại"}
        </h2>
        {mode === "analyst" && <p className="mt-1 text-xs leading-5 text-muted-foreground">Không dựng lại nội dung hội thoại thô của người dùng/trợ lý. Chỉ dùng bản tóm tắt mà API cuộc trò chuyện trả về.</p>}
      </header>

      <div className="space-y-4 p-5">
        {mode === "analyst" && (
          <>
            <dl className="grid gap-3 text-xs sm:grid-cols-2">
              <div><dt className="text-muted-foreground">Tình huống</dt><dd className="mt-0.5 font-semibold">{securityLabel(context?.scenario, "—")}</dd></div>
              <div><dt className="text-muted-foreground">Nguy cơ tiềm ẩn</dt><dd className="mt-0.5 font-semibold">{securityLabel(context?.potential_threat, "—")}</dd></div>
              <div><dt className="text-muted-foreground">Đơn vị được nhắc đến</dt><dd className="mt-0.5 font-semibold">{context?.claimed_entity ?? "—"}</dd></div>
              <div><dt className="text-muted-foreground">Hành động được yêu cầu</dt><dd className="mt-0.5 font-semibold">{securityLabel(context?.requested_action, "—")}</dd></div>
            </dl>
            {context?.urls.length ? (
              <div><p className="text-xs text-muted-foreground">URL được giữ lại</p><ul className="mt-1 space-y-1">{context.urls.map((url) => <li key={url} className="break-all font-mono text-[11px]">{url}</li>)}</ul></div>
            ) : null}
            {retainedSignals.length > 0 && <ul aria-label="Tín hiệu được giữ lại" className="flex flex-wrap gap-2">{retainedSignals.map((signal) => <li key={signal} className="rounded-full border border-border bg-muted px-2.5 py-1 text-[10px] font-semibold">{signal}</li>)}</ul>}
            <p className="border-t border-border/70 pt-3 font-mono text-[10px] text-muted-foreground">
              Ngữ cảnh v{conversation.context_version} · {conversation.summary.evidence_refs.length} mã bằng chứng được giữ lại · hết hạn <time dateTime={conversation.expires_at}>{new Date(conversation.expires_at).toLocaleString("vi-VN")}</time>
            </p>
          </>
        )}

        {issue && <div role="alert" className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs leading-5 text-amber-900 dark:text-amber-200">{issue}</div>}

        <form onSubmit={(event) => void submit(event)} className="space-y-3 border-t border-border/70 pt-4">
          <label htmlFor="resume-message" className="sr-only">Tiếp tục lượt kiểm tra với thông tin mới</label>
          <div className="relative mt-2">
            <textarea
              id="resume-message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              disabled={busy || conversation.status !== "active"}
              maxLength={5000}
              className="min-h-24 w-full resize-y rounded-xl border border-input bg-background px-3 py-2.5 pr-12 text-sm leading-6"
              placeholder="Bổ sung URL, yêu cầu hoặc tín hiệu mới…"
            />
            <button type="submit" disabled={!message.trim() || busy || conversation.status !== "active"} aria-label="Gửi thông tin bổ sung cho lượt kiểm tra" className="absolute bottom-3 right-3 grid size-9 place-items-center rounded-lg bg-primary text-primary-foreground disabled:opacity-40">
              {busy ? <Loader2 className="size-4 animate-spin" /> : <ArrowUp className="size-4" />}
            </button>
          </div>
          <p className="flex items-start gap-1.5 text-[11px] leading-5 text-muted-foreground"><ShieldCheck className="mt-0.5 size-3.5 shrink-0 text-primary" />{AUTOMATIC_LOOKUP_DISCLOSURE} Thông tin bổ sung chỉ gửi ngữ cảnh có cấu trúc, không gửi lại nội dung hội thoại thô cũ.</p>
        </form>
      </div>
    </section>
  );
}
