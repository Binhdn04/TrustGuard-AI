import { AlertTriangle } from "lucide-react";

import type { ProvisionalWarningEventV3 } from "@/types/generated/api-v3";

interface ProvisionalWarningBannerProps {
  warning: ProvisionalWarningEventV3["payload"];
}

export function ProvisionalWarningBanner({ warning }: ProvisionalWarningBannerProps) {
  return (
    <section
      aria-live="assertive"
      className="mx-auto max-w-3xl rounded-2xl border border-amber-300 bg-amber-50 p-5 text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100"
    >
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 size-5 shrink-0" />
        <div>
          <h2 className="font-bold">Cảnh báo sơ bộ — chưa phải kết luận cuối</h2>
          <p className="mt-1 text-sm leading-6">{warning.summary}</p>
          <p className="mt-2 text-xs opacity-80">
            Mức rủi ro tạm thời: {warning.risk_level}. Hệ thống vẫn đang thu thập và đối chiếu bằng chứng.
          </p>
        </div>
      </div>
    </section>
  );
}
