import { AlertCircle, MessageSquareWarning, Radio, RotateCcw } from "lucide-react";

import type {
  SecurityCaseState,
  SecurityCaseTurn,
} from "@/lib/hooks/use-security-case";
import type { AnalysisTransportState } from "@/types/analysis-view-model";

import { SecurityChatComposer } from "./security-chat-composer";

function transportLabel(transport: AnalysisTransportState): string {
  switch (transport) {
    case "connected": return "Live stream";
    case "connecting": return "Đang kết nối";
    case "reconnecting": return "Đang kết nối lại";
    case "polling_fallback": return "Polling fallback";
    default: return "Chưa kết nối";
  }
}

export function ConversationPanel({
  turns,
  state,
  transport,
  error,
  busy,
  followUp,
  onSubmit,
  onRetry,
}: {
  turns: SecurityCaseTurn[];
  state: SecurityCaseState;
  transport: AnalysisTransportState;
  error: string | null;
  busy: boolean;
  followUp?: string | null;
  onSubmit(message: string, externalLookup: boolean, officialLookup: boolean): void;
  onRetry(): void;
}) {
  return (
    <section aria-labelledby="conversation-heading" className="case-panel flex min-h-[36rem] flex-col overflow-hidden">
      <header className="flex items-center justify-between border-b border-border/70 px-4 py-3.5">
        <div>
          <p className="micro-label">01 / Conversation</p>
          <h2 id="conversation-heading" className="mt-1 text-sm font-semibold">Intake & follow-up</h2>
        </div>
        {busy && (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-2.5 py-1 text-[10px] font-bold text-primary">
            <Radio className="size-3" aria-hidden="true" />{transportLabel(transport)}
          </span>
        )}
      </header>

      <div aria-live="polite" aria-busy={busy} className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
        {turns.map((turn, index) => (
          <article key={turn.id} className="space-y-3">
            <div className="ml-auto max-w-[92%] rounded-2xl rounded-br-sm bg-foreground px-4 py-3 text-sm leading-6 text-background">
              <p className="mb-1 text-[9px] font-bold uppercase tracking-[0.18em] opacity-60">Input {index + 1}</p>
              <p className="whitespace-pre-wrap break-words">{turn.message}</p>
            </div>
            {turn.result?.scope_decision === "OUT_OF_SCOPE_GENERAL_FACT_CHECK" && (
              <div className="max-w-[94%] rounded-2xl rounded-bl-sm border border-border bg-muted/40 p-4 text-sm">
                <p className="font-semibold">Nội dung này nằm ngoài phạm vi Security Triage</p>
                <p className="mt-1 leading-6 text-muted-foreground">{turn.result.boundary_message}</p>
              </div>
            )}
            {turn.result?.scope_decision === "NEED_MORE_INFO" && (
              <div className="max-w-[94%] rounded-2xl rounded-bl-sm border border-amber-500/25 bg-amber-500/8 p-4 text-sm">
                <p className="flex items-center gap-2 font-semibold"><MessageSquareWarning className="size-4" />Cần thêm thông tin</p>
                <p className="mt-1 leading-6">{turn.result.follow_up_question}</p>
              </div>
            )}
          </article>
        ))}

        {busy && (
          <div role="status" className="max-w-[94%] rounded-2xl rounded-bl-sm border border-primary/20 bg-primary/5 p-4">
            <div className="flex items-center gap-3">
              <span className="relative flex size-2.5">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary opacity-40" />
                <span className="relative inline-flex size-2.5 rounded-full bg-primary" />
              </span>
              <div>
                <p className="text-sm font-semibold">Analysis lifecycle đang chạy</p>
                <p className="mt-0.5 text-xs text-muted-foreground">{transportLabel(transport)}</p>
              </div>
            </div>
            {state === "PROVISIONAL_WARNING" && (
              <p className="mt-3 text-xs leading-5 text-amber-700 dark:text-amber-300">
                Có tín hiệu rủi ro cao tạm thời từ API; đây chưa phải kết luận cuối.
              </p>
            )}
          </div>
        )}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/8 p-3 text-sm text-rose-700 dark:text-rose-300">
            <p className="flex items-center gap-2 font-semibold"><AlertCircle className="size-4" />Không thể hoàn tất đánh giá</p>
            <p className="mt-1 text-xs leading-5">{error}</p>
            <button type="button" onClick={onRetry} className="mt-3 inline-flex items-center gap-1.5 text-xs font-bold underline underline-offset-4">
              <RotateCcw className="size-3.5" />Thử lại case này
            </button>
          </div>
        )}

        {state === "FAILED" && !error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/8 p-3 text-sm text-rose-700 dark:text-rose-300">
            <p className="flex items-center gap-2 font-semibold"><AlertCircle className="size-4" />Analysis đã kết thúc với trạng thái failed</p>
            <p className="mt-1 text-xs leading-5">Không có verdict cuối để hiển thị. Bạn có thể thử chạy lại case này.</p>
            <button type="button" onClick={onRetry} className="mt-3 inline-flex items-center gap-1.5 text-xs font-bold underline underline-offset-4">
              <RotateCcw className="size-3.5" />Thử lại case này
            </button>
          </div>
        )}
      </div>

      {!busy && (
        <div className="border-t border-border/70 bg-background/35 p-3">
          <SecurityChatComposer onSubmit={onSubmit} busy={false} followUp={followUp} variant="compact" />
        </div>
      )}
    </section>
  );
}
