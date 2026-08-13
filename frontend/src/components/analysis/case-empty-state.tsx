import type { ReactNode } from "react";
import { ArrowDown, Fingerprint, Link2, MessageSquareText, Shield } from "lucide-react";

export function CaseEmptyState({ composer }: { composer: ReactNode }) {
  return (
    <div className="mx-auto grid min-h-[calc(100vh-9rem)] max-w-6xl items-center gap-10 py-4 lg:grid-cols-[0.9fr_1.1fr] lg:py-10">
      <section aria-labelledby="intake-heading" className="relative overflow-hidden px-2 py-4 sm:px-5 lg:py-10">
        <div className="absolute -left-24 top-0 -z-10 size-80 rounded-full border border-primary/10" aria-hidden="true" />
        <div className="absolute -left-10 top-14 -z-10 size-52 rounded-full border border-primary/15" aria-hidden="true" />
        <p className="micro-label text-primary">CASE INTAKE / 01</p>
        <h1 id="intake-heading" className="mt-4 max-w-2xl text-4xl font-semibold leading-[1.03] tracking-[-0.04em] sm:text-5xl lg:text-6xl">
          Biến tín hiệu đáng ngờ thành một hồ sơ có thể kiểm chứng.
        </h1>
        <p className="mt-6 max-w-xl text-base leading-7 text-muted-foreground">
          Bắt đầu bằng tin nhắn, URL hoặc hành động được yêu cầu. Chat là điểm vào; khi có case,
          workspace sẽ tách hội thoại, điều tra và hành động.
        </p>

        <div className="mt-8 grid gap-3 sm:grid-cols-3">
          {[
            { icon: MessageSquareText, label: "Context", copy: "Nội dung bạn cung cấp" },
            { icon: Fingerprint, label: "Signals", copy: "Dữ liệu API xác nhận" },
            { icon: Shield, label: "Action", copy: "Hướng xử lý an toàn" },
          ].map(({ icon: Icon, label, copy }, index) => (
            <div key={label} className="border-l border-border pl-3">
              <div className="flex items-center gap-2 text-xs font-bold"><Icon className="size-4 text-primary" />0{index + 1} · {label}</div>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy}</p>
            </div>
          ))}
        </div>
      </section>

      <section aria-label="Tạo case mới" className="case-panel relative overflow-hidden p-4 sm:p-6">
        <div className="mb-5 flex items-center justify-between border-b border-border/70 pb-4">
          <div>
            <p className="micro-label">SECURE INPUT</p>
            <p className="mt-1 text-sm font-semibold">Mở một trường hợp mới</p>
          </div>
          <span className="grid size-9 place-items-center rounded-full border border-border bg-background text-primary">
            <Link2 className="size-4" aria-hidden="true" />
          </span>
        </div>
        {composer}
        <p className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
          <ArrowDown className="size-3.5" aria-hidden="true" />
          Kết quả sẽ mở trong investigation workspace, không phải một dashboard mô phỏng.
        </p>
      </section>
    </div>
  );
}
