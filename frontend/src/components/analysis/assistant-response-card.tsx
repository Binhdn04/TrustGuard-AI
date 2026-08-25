import { Bot } from "lucide-react";

import { type SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type { AssistantResponseV4 } from "@/types/generated/api-v4";

function SimpleAssistantMessage({ response }: { response: AssistantResponseV4 }) {
  return (
    <section
      aria-label="Phản hồi của trợ lý bảo mật"
      className="max-w-[94%] rounded-2xl rounded-bl-sm border border-border bg-muted/40 px-4 py-3 text-sm"
    >
      <p className="whitespace-pre-wrap break-words leading-6">{response.summary}</p>
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
