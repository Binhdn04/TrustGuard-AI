import { Bot, ChevronDown, CircleHelp, ShieldCheck } from "lucide-react";

import {
  SECURITY_ACTION_LABELS,
  type SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import type { AssistantResponseV4 } from "@/types/generated/api-v4";

function SimpleAssistantMessage({ response }: { response: AssistantResponseV4 }) {
  const reasons = response.top_reasons.slice(0, 3);
  const actions = response.immediate_steps.slice(0, 3);
  return (
    <section
      aria-label="Phản hồi của trợ lý bảo mật"
      className="max-w-[94%] rounded-2xl rounded-bl-sm border border-border bg-muted/40 px-4 py-3 text-sm"
    >
      <p className="whitespace-pre-wrap break-words leading-6">{response.summary}</p>
      <details className="group mt-3">
        <summary className="inline-flex cursor-pointer list-none items-center gap-2 rounded-xl border border-primary/25 bg-background px-3 py-2 text-xs font-semibold text-primary shadow-sm hover:bg-primary/5">
          Xem lý do và hướng dẫn chi tiết
          <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" aria-hidden="true" />
        </summary>
        <div className="mt-3 space-y-4 border-t border-border/70 pt-3">
          {actions.length > 0 && (
            <div>
              <p className="flex items-center gap-1.5 text-xs font-semibold">
                <ShieldCheck className="size-3.5 text-primary" aria-hidden="true" />
                Các bước nên làm
              </p>
              <ol className="mt-2 space-y-1.5 text-xs leading-5">
                {actions.map((step, index) => (
                  <li key={step.action} className="flex gap-2">
                    <span className="font-bold text-primary">{index + 1}.</span>
                    <span>{SECURITY_ACTION_LABELS[step.action]}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {reasons.length > 0 && (
            <div>
              <p className="text-xs font-semibold">Vì sao mình đưa ra lời khuyên này?</p>
              <ul className="mt-2 space-y-1.5 text-xs leading-5 text-muted-foreground">
                {reasons.map((reason, index) => (
                  <li key={`${reason.text}:${index}`}>• {reason.text}</li>
                ))}
              </ul>
            </div>
          )}
          {response.uncertainties.length > 0 && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/7 p-3">
              <p className="flex items-center gap-1.5 text-xs font-semibold">
                <CircleHelp className="size-3.5" aria-hidden="true" />
                Điều chưa xác minh được
              </p>
              <ul className="mt-1.5 space-y-1 text-xs leading-5 text-muted-foreground">
                {response.uncertainties.map((item) => <li key={item}>• {item}</li>)}
              </ul>
            </div>
          )}
          {response.follow_up_offer && (
            <p className="text-xs leading-5 text-muted-foreground">{response.follow_up_offer}</p>
          )}
        </div>
      </details>
    </section>
  );
}

function AnalystAssistantResponse({ response }: { response: AssistantResponseV4 }) {
  return (
    <section
      aria-label="Phản hồi của trợ lý bảo mật"
      className="max-w-[94%] rounded-2xl rounded-bl-sm border border-primary/20 bg-primary/5 p-4 text-sm"
    >
      <div className="flex items-center gap-2">
        <span className="grid size-7 place-items-center rounded-lg bg-primary/10 text-primary">
          <Bot className="size-4" aria-hidden="true" />
        </span>
        <div>
          <p className="font-semibold">Trợ lý bảo mật</p>
          <p className="text-[10px] text-muted-foreground">
            {response.generation_mode === "ai" ? "AI · đã kiểm tra grounding" : "Trả lời từ policy và bằng chứng"}
          </p>
        </div>
      </div>
      <p className="mt-3 whitespace-pre-wrap break-words leading-6">{response.summary}</p>
      {response.top_reasons.length > 0 && (
        <div className="mt-3 border-t border-primary/15 pt-3">
          <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground">Lý do chính</p>
          <ul className="mt-2 space-y-2">
            {response.top_reasons.map((reason, index) => (
              <li key={`${reason.text}:${index}`} className="break-words leading-5">
                <span aria-hidden="true">• </span>{reason.text}
                <span className="mt-1 block font-mono text-[10px] text-muted-foreground">
                  {reason.evidence_refs.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {response.uncertainties.length > 0 && (
        <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/7 p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold">
            <CircleHelp className="size-3.5" aria-hidden="true" />Điểm chưa chắc chắn
          </p>
          <ul className="mt-1.5 space-y-1 text-xs leading-5 text-muted-foreground">
            {response.uncertainties.map((item) => <li key={item}>• {item}</li>)}
          </ul>
        </div>
      )}
      {response.follow_up_offer && (
        <p className="mt-3 text-xs leading-5 text-muted-foreground">{response.follow_up_offer}</p>
      )}
      <p className="mt-3 border-t border-primary/15 pt-2 text-[10px] leading-4 text-muted-foreground">
        {response.generation_mode === "ai"
          ? "Phần diễn giải được xử lý bởi nhà cung cấp AI; verdict và hành động vẫn do policy xác định."
          : "Phản hồi được tạo trực tiếp từ verdict, bằng chứng và hành động đã kiểm chứng."}
        {` · ${response.response_version}`}
      </p>
    </section>
  );
}

export function AssistantResponseCard({
  response,
  mode,
}: {
  response: AssistantResponseV4;
  mode: SecurityPresentationMode;
}) {
  return mode === "simple"
    ? <SimpleAssistantMessage response={response} />
    : <AnalystAssistantResponse response={response} />;
}
