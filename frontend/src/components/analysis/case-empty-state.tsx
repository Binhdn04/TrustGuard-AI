import type { ReactNode } from "react";

export function CaseEmptyState({ composer }: { composer: ReactNode }) {
  return (
    <div className="mx-auto flex min-h-[calc(100vh-9rem)] max-w-4xl items-center justify-center py-8 lg:py-12">
      <section aria-labelledby="intake-heading" className="relative w-full text-center">
        <div className="absolute left-1/2 top-0 -z-10 size-80 -translate-x-1/2 rounded-full border border-primary/10" aria-hidden="true" />
        <div className="absolute left-1/2 top-12 -z-10 size-52 -translate-x-1/2 rounded-full border border-primary/15" aria-hidden="true" />
        <h1 id="intake-heading" className="mx-auto max-w-3xl text-4xl font-semibold leading-[1.05] tracking-[-0.04em] sm:text-5xl lg:text-6xl">
          Bạn muốn kiểm tra điều gì?
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg">
          Tin nhắn lạ, link đáng ngờ hay thông tin khó xác minh — cứ gửi mình
        </p>

        <section aria-label="Tạo case mới" className="case-panel relative mx-auto mt-8 max-w-3xl overflow-hidden p-4 text-left shadow-sm sm:p-6">
          {composer}
        </section>
      </section>
    </div>
  );
}
