import { Bot, CircleHelp } from "lucide-react";

import type { SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type { AssistantResponseV4 } from "@/types/generated/api-v4";

export function AssistantResponseCard({
  response,
  mode,
}: {
  response: AssistantResponseV4;
  mode: SecurityPresentationMode;
}) {
  const reasons = mode === "analyst" ? response.top_reasons : [];
  return (
    <section aria-label="Phản hồi của trợ lý bảo mật" className="max-w-[94%] rounded-2xl rounded-bl-sm border border-primary/20 bg-primary/5 p-4 text-sm">
      <div className="flex items-center gap-2">
        <span className="grid size-7 place-items-center rounded-lg bg-primary/10 text-primary"><Bot className="size-4" aria-hidden="true" /></span>
        <div>
          <p className="font-semibold">Trợ lý bảo mật</p>
          <p className="text-[10px] text-muted-foreground">
            {response.generation_mode === "ai" ? "AI · đã kiểm tra grounding" : "Trả lời từ policy và bằng chứng"}
          </p>
        </div>
      </div>

      <p className="mt-3 whitespace-pre-wrap break-words leading-6">{response.summary}</p>
      {reasons.length > 0 && (
        <div className="mt-3 border-t border-primary/15 pt-3">
          <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground">Lý do chính</p>
          <ul className="mt-2 space-y-2">
            {reasons.map((reason, index) => (
              <li key={`${reason.text}:${index}`} className="break-words leading-5">
                <span aria-hidden="true">• </span>{reason.text}
                {mode === "analyst" && (
                  <span className="mt-1 block font-mono text-[10px] text-muted-foreground">
                    {reason.evidence_refs.join(", ")}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {mode === "analyst" && response.uncertainties.length > 0 && (
        <div className="mt-3 rounded-xl border border-amber-500/20 bg-amber-500/7 p-3">
          <p className="flex items-center gap-1.5 text-xs font-semibold"><CircleHelp className="size-3.5" aria-hidden="true" />Điểm chưa chắc chắn</p>
          <ul className="mt-1.5 space-y-1 text-xs leading-5 text-muted-foreground">
            {response.uncertainties.map((item) => <li key={item}>• {item}</li>)}
          </ul>
        </div>
      )}
      {response.follow_up_offer && <p className="mt-3 text-xs leading-5 text-muted-foreground">{response.follow_up_offer}</p>}
      <p className="mt-3 border-t border-primary/15 pt-2 text-[10px] leading-4 text-muted-foreground">
        {response.generation_mode === "ai"
          ? "Phần diễn giải được xử lý bởi nhà cung cấp AI; verdict và hành động vẫn do policy xác định."
          : "Phản hồi được tạo trực tiếp từ verdict, bằng chứng và hành động đã kiểm chứng."}
        {mode === "analyst" && ` · ${response.response_version}`}
      </p>
    </section>
  );
}
