import { SearchIcon } from "@/components/ui/icons";
import type { Evidence } from "@/types/analysis";

const typeLabels: Record<Evidence["type"], string> = {
  url_rule: "URL rule",
  domain_reputation: "Domain reputation",
  redirect: "Redirect",
  blacklist: "Blacklist",
  domain_registration: "Đăng ký tên miền",
  fact_check: "Fact-check",
  official_source: "Nguồn chính thức",
  user_report: "Báo cáo người dùng",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("vi-VN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}

export function EvidenceList({ items }: { items: Evidence[] }) {
  return (
    <section aria-labelledby="evidence-heading" className="rounded-3xl border border-border bg-card p-5 sm:p-7">
      <div className="flex items-center gap-3">
        <span className="grid size-9 place-items-center rounded-xl bg-cyan-500/10 text-cyan-600 dark:text-cyan-400">
          <SearchIcon className="size-5" />
        </span>
        <div>
          <h2 id="evidence-heading" className="font-bold text-foreground">Bằng chứng</h2>
          <p className="text-xs text-muted-foreground">Các tín hiệu được dùng để đánh giá</p>
        </div>
      </div>

      {items.length === 0 ? (
        <p className="mt-5 rounded-xl bg-muted/50 p-4 text-sm text-muted-foreground">
          Chưa thu thập được bằng chứng có thể đối chiếu.
        </p>
      ) : (
        <ul className="mt-5 divide-y divide-border">
          {items.map((item, index) => (
            <li key={`${item.source}-${index}`} className="py-4 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-muted px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide text-muted-foreground">
                  {typeLabels[item.type]}
                </span>
                <span className="text-xs text-muted-foreground/70">{formatTime(item.observed_at)}</span>
              </div>
              <h3 className="mt-2 text-sm font-bold text-foreground">{item.title}</h3>
              <p className="mt-1 text-sm leading-6 text-muted-foreground">{item.finding}</p>
              {item.url && (
                <code className="mt-2 block break-all rounded-lg bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
                  {item.url}
                </code>
              )}
              <p className="mt-2 text-xs font-medium text-muted-foreground/70">Nguồn: {item.source}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
