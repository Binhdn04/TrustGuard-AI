import { useState } from "react";
import { ChevronDown, GitBranch, Search } from "lucide-react";

import {
  presentCampaign,
  type CampaignSignalPresentation,
} from "@/lib/presentation/campaign-presentation";
import { statusLabel } from "@/lib/presentation/security-labels";
import type {
  SecurityCampaignAuditRecordV4,
  SecurityCampaignPageV4,
  SecurityCampaignRecordV4,
  SecurityCampaignReviewerStatusV4,
} from "@/types/generated/api-v4";

export interface CampaignReviewQuery {
  q: string;
  status: "all" | SecurityCampaignReviewerStatusV4;
  page: number;
}

type ReviewDecision = "confirmed" | "rejected";

function SignalBadge({ signal, total }: { signal: CampaignSignalPresentation; total: number }) {
  return (
    <span className="inline-flex max-w-full items-center gap-1.5 rounded-full border border-border bg-background px-2.5 py-1 text-xs">
      <span className="truncate">{signal.label}</span>
      <strong className="shrink-0 text-primary">{signal.count}/{total}</strong>
    </span>
  );
}

function CampaignCard({ record, selected, onSelect }: {
  record: SecurityCampaignRecordV4;
  selected: boolean;
  onSelect: () => void;
}) {
  const presentation = presentCampaign(record);
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onSelect}
      className="w-full rounded-xl border border-border bg-card p-4 text-left transition hover:bg-muted/35 aria-pressed:border-primary aria-pressed:bg-primary/5"
    >
      <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">
        {statusLabel(record.reviewer_status)}
      </span>
      <strong className="mt-2 block leading-5">{presentation.title}</strong>
      {presentation.subtitle && (
        <span className="mt-1 block text-sm text-muted-foreground">{presentation.subtitle}</span>
      )}
      <span className="mt-2 flex flex-wrap gap-1.5">
        {presentation.topSignals.slice(0, 2).map((signal) => (
          <SignalBadge key={signal.raw} signal={signal} total={record.analysis_ids.length} />
        ))}
        {presentation.topSignals.length === 0 && (
          <span className="text-xs text-muted-foreground">Chỉ có tín hiệu kỹ thuật</span>
        )}
      </span>
      <span className="mt-3 block text-xs text-muted-foreground">
        {record.analysis_ids.length} phân tích · {record.evidence_refs.length} bằng chứng
      </span>
      <span className="mt-1 block text-[10px] text-muted-foreground">
        {new Date(record.window_started_at).toLocaleString("vi-VN")} – {new Date(record.window_ended_at).toLocaleString("vi-VN")}
      </span>
    </button>
  );
}

function SignalSection({ title, signals, total }: {
  title: string;
  signals: CampaignSignalPresentation[];
  total: number;
}) {
  if (signals.length === 0) return null;
  return (
    <section>
      <h4 className="micro-label">{title}</h4>
      <div className="mt-2 flex flex-wrap gap-2">
        {signals.map((signal) => <SignalBadge key={signal.raw} signal={signal} total={total} />)}
      </div>
    </section>
  );
}

function CampaignDetail({ selected, audit, busy, onReview }: {
  selected: SecurityCampaignRecordV4;
  audit: SecurityCampaignAuditRecordV4[];
  busy: boolean;
  onReview: (record: SecurityCampaignRecordV4, decision: ReviewDecision, note: string) => Promise<void>;
}) {
  const [decision, setDecision] = useState<ReviewDecision>("confirmed");
  const [note, setNote] = useState("");
  const presentation = presentCampaign(selected);
  const total = selected.analysis_ids.length;

  return (
    <div className="space-y-5">
      <header>
        <span className="micro-label">{statusLabel(selected.reviewer_status)}</span>
        <h3 className="mt-1 text-xl font-bold leading-7">{presentation.title}</h3>
        {presentation.subtitle && <p className="mt-1 text-sm text-muted-foreground">{presentation.subtitle}</p>}
        <p className="mt-2 text-xs text-muted-foreground">
          {new Date(selected.window_started_at).toLocaleString("vi-VN")} → {new Date(selected.window_ended_at).toLocaleString("vi-VN")}
        </p>
      </header>

      <section aria-labelledby="campaign-summary-heading" className="rounded-xl border border-primary/20 bg-primary/5 p-4">
        <h4 id="campaign-summary-heading" className="text-xs font-bold uppercase tracking-wide text-primary">
          Tóm tắt để duyệt
        </h4>
        <div className="mt-2 space-y-1 text-sm leading-6">
          {presentation.summary.map((sentence) => <p key={sentence}>{sentence}</p>)}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Đây là phần trình bày lại tín hiệu hiện có, không phải kết luận bảo mật.
        </p>
      </section>

      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div className="rounded-xl bg-muted/55 p-3">
          <dt className="text-xs text-muted-foreground">Phân tích liên quan</dt>
          <dd className="mt-1 text-2xl font-bold">{total}</dd>
        </div>
        <div className="rounded-xl bg-muted/55 p-3">
          <dt className="text-xs text-muted-foreground">Bằng chứng</dt>
          <dd className="mt-1 text-2xl font-bold">{selected.evidence_refs.length}</dd>
        </div>
      </dl>

      <SignalSection title="Tín hiệu chính" signals={presentation.groups.primary} total={total} />

      {presentation.groups.destination.length > 0 && (
        <section>
          <h4 className="micro-label">Domain và chuyển hướng liên quan</h4>
          <dl className="mt-2 divide-y divide-border rounded-xl border border-border">
            {presentation.groups.destination.map((signal) => (
              <div key={signal.raw} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                <div className="min-w-0">
                  <dt className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    {signal.prefix === "redirect" ? "Chuyển hướng" : "Domain"}
                  </dt>
                  <dd className="break-all font-medium">{signal.label}</dd>
                </div>
                <dd className="shrink-0 font-bold text-primary">{signal.count}/{total}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <SignalSection title="Dấu hiệu bổ trợ" signals={presentation.groups.supporting} total={total} />

      <details className="group rounded-xl border border-border p-4">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold">
          Dữ liệu kỹ thuật
          <ChevronDown className="size-4 shrink-0 transition-transform group-open:rotate-180" />
        </summary>
        <div className="mt-4 space-y-4 border-t border-border pt-4 text-xs">
          <div>
            <h4 className="font-semibold">Giả thuyết gốc</h4>
            <p className="mt-1 break-words font-mono text-[10px] text-muted-foreground">{selected.hypothesis}</p>
          </div>
          <div>
            <h4 className="font-semibold">Toàn bộ tín hiệu thô</h4>
            <dl className="mt-2 space-y-1">
              {Object.entries(selected.aggregate_signals).map(([signal, count]) => (
                <div key={signal} className="flex justify-between gap-3 rounded-lg bg-muted/50 px-2 py-1.5">
                  <dt className="break-all font-mono text-[10px]">{signal}</dt>
                  <dd className="font-bold">{count}</dd>
                </div>
              ))}
            </dl>
          </div>
          {(presentation.groups.technical.length > 0 || presentation.groups.other.length > 0) && (
            <div>
              <h4 className="font-semibold">Diễn giải tín hiệu kỹ thuật</h4>
              <ul className="mt-2 space-y-1 text-muted-foreground">
                {[...presentation.groups.technical, ...presentation.groups.other].map((signal) => (
                  <li key={signal.raw}>{signal.label} · {signal.count}/{total}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <h4 className="font-semibold">Phân tích thành viên</h4>
              <ul className="mt-2 max-h-36 space-y-1 overflow-auto">
                {selected.analysis_ids.map((id) => <li key={id} className="break-all font-mono text-[10px]">{id}</li>)}
              </ul>
            </div>
            <div>
              <h4 className="font-semibold">Mã bằng chứng</h4>
              <ul className="mt-2 max-h-36 space-y-1 overflow-auto">
                {selected.evidence_refs.map((ref) => <li key={ref} className="break-all font-mono text-[10px]">{ref}</li>)}
              </ul>
            </div>
          </div>
          <p className="font-mono text-[10px] text-muted-foreground">
            {selected.clustering_version} · {selected.campaign_id}
          </p>
        </div>
      </details>

      {selected.reviewer_status === "pending_review" ? (
        <section aria-labelledby="campaign-decision-heading" className="rounded-xl border border-border p-4">
          <h4 id="campaign-decision-heading" className="text-sm font-semibold">Quyết định của người duyệt</h4>
          <fieldset className="mt-3 grid gap-2 sm:grid-cols-2">
            <legend className="sr-only">Quyết định</legend>
            <label className="flex cursor-pointer gap-3 rounded-xl border border-border p-3 has-[:checked]:border-primary has-[:checked]:bg-primary/5">
              <input type="radio" name="campaign-decision" value="confirmed" checked={decision === "confirmed"} onChange={() => setDecision("confirmed")} className="mt-1" />
              <span><strong className="block text-sm">Xác nhận chiến dịch</strong><span className="mt-0.5 block text-xs text-muted-foreground">Các tín hiệu đủ nhất quán để xác nhận cụm.</span></span>
            </label>
            <label className="flex cursor-pointer gap-3 rounded-xl border border-border p-3 has-[:checked]:border-primary has-[:checked]:bg-primary/5">
              <input type="radio" name="campaign-decision" value="rejected" checked={decision === "rejected"} onChange={() => setDecision("rejected")} className="mt-1" />
              <span><strong className="block text-sm">Không xác nhận</strong><span className="mt-0.5 block text-xs text-muted-foreground">Tín hiệu chưa đủ hoặc không cùng một chiến dịch.</span></span>
            </label>
          </fieldset>
          <label htmlFor="campaign-note" className="mt-3 block text-xs font-semibold">Ghi chú của người duyệt</label>
          <textarea
            id="campaign-note"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Nêu tín hiệu đã đối chiếu và lý do xác nhận hoặc không xác nhận."
            className="mt-1 min-h-24 w-full rounded-xl border border-border bg-background p-3 text-sm"
          />
          <button
            type="button"
            disabled={!note.trim() || busy}
            onClick={() => void onReview(selected, decision, note.trim()).then(() => setNote(""))}
            className="mt-3 w-full rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45"
          >
            {busy ? "Đang lưu…" : "Gửi kết quả duyệt"}
          </button>
        </section>
      ) : (
        <section className="rounded-xl bg-muted/60 p-3 text-sm">
          <strong>{statusLabel(selected.reviewer_status)}</strong>
          <p className="mt-1 text-muted-foreground">{selected.reviewer_id}: {selected.review_note}</p>
        </section>
      )}

      <section>
        <h4 className="micro-label">Lịch sử duyệt chiến dịch</h4>
        <div className="mt-2 space-y-2">
          {audit.map((record) => (
            <article key={record.audit_id} className="rounded-xl border border-border p-3 text-xs">
              <strong>{statusLabel(record.previous_status)} → {statusLabel(record.status)}</strong>
              <p className="mt-1 text-muted-foreground">{record.reviewer_id}: {record.note}</p>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                {record.clustering_version} · {new Date(record.occurred_at).toLocaleString("vi-VN")} · {record.evidence_refs.length} bằng chứng
              </p>
            </article>
          ))}
          {audit.length === 0 && <p className="text-xs text-muted-foreground">Chưa có lịch sử duyệt chiến dịch.</p>}
        </div>
      </section>
    </div>
  );
}

export function CampaignReview({ page, query, selected, audit, loading, detailLoading, busy, error, onQueryChange, onSelect, onReview, onRetry }: {
  page: SecurityCampaignPageV4 | null;
  query: CampaignReviewQuery;
  selected: SecurityCampaignRecordV4 | null;
  audit: SecurityCampaignAuditRecordV4[];
  loading: boolean;
  detailLoading: boolean;
  busy: boolean;
  error: string | null;
  onQueryChange: (query: CampaignReviewQuery) => void;
  onSelect: (record: SecurityCampaignRecordV4) => Promise<void>;
  onReview: (record: SecurityCampaignRecordV4, decision: ReviewDecision, note: string) => Promise<void>;
  onRetry: () => void;
}) {
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 10)));
  return (
    <section aria-labelledby="campaign-review-heading" className="space-y-4">
      <header>
        <p className="micro-label">Cụm tín hiệu V4 có thể giải thích</p>
        <h2 id="campaign-review-heading" className="mt-1 text-xl font-bold">Duyệt chiến dịch</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Tín hiệu được trình bày lại để dễ đối chiếu; quyết định vẫn do người duyệt xác nhận.
        </p>
      </header>
      <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
        <label className="relative">
          <span className="sr-only">Tìm chiến dịch</span>
          <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
          <input aria-label="Tìm chiến dịch" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" placeholder="Tên đơn vị, domain hoặc tín hiệu…" />
        </label>
        <select aria-label="Lọc chiến dịch theo trạng thái" value={query.status} onChange={(event) => onQueryChange({ ...query, status: event.target.value as CampaignReviewQuery["status"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm">
          <option value="all">Tất cả trạng thái</option>
          <option value="pending_review">{statusLabel("pending_review")}</option>
          <option value="confirmed">{statusLabel("confirmed")}</option>
          <option value="rejected">{statusLabel("rejected")}</option>
        </select>
      </div>
      {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
      <div className="grid gap-4 xl:grid-cols-[minmax(20rem,0.8fr)_minmax(24rem,1.2fr)]">
        <div className="space-y-2">
          {loading ? (
            <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải chiến dịch…</p>
          ) : page?.items.map((record) => (
            <CampaignCard
              key={record.campaign_id}
              record={record}
              selected={selected?.campaign_id === record.campaign_id}
              onSelect={() => void onSelect(record)}
            />
          ))}
          {!loading && page?.items.length === 0 && <p className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">Không có chiến dịch phù hợp.</p>}
          <div className="flex items-center justify-end gap-2 text-xs">
            <button aria-label="Trang chiến dịch trước" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>
            {query.page}/{lastPage}
            <button aria-label="Trang chiến dịch sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button>
          </div>
        </div>
        <div className="rounded-2xl border border-border bg-card p-5">
          {!selected && !detailLoading && <div className="grid min-h-64 place-items-center text-center text-sm text-muted-foreground"><div><GitBranch className="mx-auto mb-2 size-7" />Chọn một chiến dịch để xem tóm tắt.</div></div>}
          {detailLoading && <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang tải chi tiết và lịch sử chiến dịch…</p>}
          {selected && !detailLoading && <CampaignDetail key={selected.campaign_id} selected={selected} audit={audit} busy={busy} onReview={onReview} />}
        </div>
      </div>
    </section>
  );
}
