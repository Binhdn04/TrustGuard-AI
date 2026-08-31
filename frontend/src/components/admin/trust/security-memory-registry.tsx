import { useState } from "react";
import { ChevronDown, Database, Search } from "lucide-react";

import { presentSecurityMemory } from "@/lib/presentation/security-memory-presentation";
import { riskLabel, verdictLabel } from "@/lib/presentation/security-labels";
import type {
  SecurityMemoryAdminVerdictV4,
  SecurityMemoryAuditRecordV4,
  SecurityMemoryPageV4,
  SecurityMemoryRecordV4,
  SecurityMemoryReviewedVerdictV4,
  SecurityRiskV4,
} from "@/types/generated/api-v4";

export interface SecurityMemoryQueryState {
  q: string;
  risk: "all" | SecurityRiskV4;
  verdict: "all" | SecurityMemoryAdminVerdictV4;
  page: number;
}

function MemoryCard({ record, selected, onSelect }: {
  record: SecurityMemoryRecordV4;
  selected: boolean;
  onSelect: () => void;
}) {
  const presentation = presentSecurityMemory(record);
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={onSelect}
      className="w-full rounded-xl border border-border bg-card p-4 text-left transition hover:bg-muted/35 aria-pressed:border-primary aria-pressed:bg-primary/5"
    >
      <span className="flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">
          {verdictLabel(record.admin_verdict)}
        </span>
        <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-bold text-primary">
          {riskLabel(record.risk)}
        </span>
      </span>
      <strong className="mt-2 block">{presentation.title}</strong>
      {presentation.subtitle && <span className="mt-1 block text-xs text-muted-foreground">{presentation.subtitle}</span>}
      <span className="mt-2 block text-xs text-muted-foreground">
        {presentation.scenarioLabel} · {presentation.actionLabel}
      </span>
      <span className="mt-2 block text-[10px] text-muted-foreground">
        {presentation.reportLabel} · {presentation.evidenceLabel}
      </span>
    </button>
  );
}

function MemoryDetail({ selected, audit, busy, onCorrect }: {
  selected: SecurityMemoryRecordV4;
  audit: SecurityMemoryAuditRecordV4[];
  busy: boolean;
  onCorrect: (record: SecurityMemoryRecordV4, verdict: SecurityMemoryReviewedVerdictV4, note: string) => Promise<void>;
}) {
  const initialVerdict = selected.admin_verdict === "unreviewed" ? "suspicious" : selected.admin_verdict;
  const [verdict, setVerdict] = useState<SecurityMemoryReviewedVerdictV4>(initialVerdict);
  const [note, setNote] = useState("");
  const presentation = presentSecurityMemory(selected);

  return (
    <div className="space-y-5">
      <header>
        <p className="micro-label">Bản ghi bảo mật đang chọn</p>
        <h3 className="mt-1 text-xl font-bold">{presentation.title}</h3>
        {presentation.subtitle && <p className="mt-1 text-sm text-muted-foreground">{presentation.subtitle}</p>}
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="rounded-full bg-muted px-2.5 py-1 text-xs font-semibold">
            {verdictLabel(selected.admin_verdict)}
          </span>
          <span className="rounded-full bg-primary/10 px-2.5 py-1 text-xs font-semibold text-primary">
            {riskLabel(selected.risk)}
          </span>
        </div>
      </header>

      <section aria-labelledby="memory-summary-heading" className="rounded-xl border border-primary/20 bg-primary/5 p-4">
        <h4 id="memory-summary-heading" className="text-xs font-bold uppercase tracking-wide text-primary">
          Tóm tắt để đánh giá
        </h4>
        <div className="mt-2 space-y-1 text-sm leading-6">
          {presentation.summary.map((sentence) => <p key={sentence}>{sentence}</p>)}
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Tóm tắt này chỉ trình bày lại dữ liệu của lần check, không thay đổi kết quả.
        </p>
      </section>

      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div className="rounded-xl bg-muted/55 p-3">
          <dt className="text-xs text-muted-foreground">Báo cáo liên kết</dt>
          <dd className="mt-1 font-semibold">{presentation.reportLabel}</dd>
        </div>
        <div className="rounded-xl bg-muted/55 p-3">
          <dt className="text-xs text-muted-foreground">Bằng chứng</dt>
          <dd className="mt-1 font-semibold">{presentation.evidenceLabel}</dd>
        </div>
      </dl>

      <section>
        <h4 className="micro-label">Thông tin để đánh giá</h4>
        <dl className="mt-2 divide-y divide-border rounded-xl border border-border text-sm">
          <div className="grid gap-1 px-3 py-2.5 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">Mối đe dọa</dt>
            <dd className="font-medium">{presentation.threatLabel}</dd>
          </div>
          <div className="grid gap-1 px-3 py-2.5 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">Bối cảnh</dt>
            <dd className="font-medium">{presentation.scenarioLabel}</dd>
          </div>
          <div className="grid gap-1 px-3 py-2.5 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">Hành động</dt>
            <dd className="font-medium">{presentation.actionLabel}</dd>
          </div>
          <div className="grid gap-1 px-3 py-2.5 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">Domain liên quan</dt>
            <dd className="break-all font-medium">{selected.canonical_domains.join(", ") || "Chưa ghi nhận"}</dd>
          </div>
          <div className="grid gap-1 px-3 py-2.5 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">Chuyển hướng</dt>
            <dd className="break-all font-medium">{selected.redirect_targets.join(", ") || "Chưa ghi nhận"}</dd>
          </div>
        </dl>
      </section>

      {presentation.patternLabels.length > 0 && (
        <section>
          <h4 className="micro-label">Dấu hiệu bổ trợ</h4>
          <div className="mt-2 flex flex-wrap gap-2">
            {presentation.patternLabels.map((pattern) => (
              <span key={pattern} className="rounded-full border border-border bg-background px-2.5 py-1 text-xs">
                {pattern}
              </span>
            ))}
          </div>
        </section>
      )}

      <section>
        <h4 className="micro-label">Thời gian ghi nhận</h4>
        <dl className="mt-2 grid gap-3 text-sm sm:grid-cols-2">
          <div className="rounded-xl border border-border p-3">
            <dt className="text-xs text-muted-foreground">Lần đầu</dt>
            <dd className="mt-1 font-medium">{new Date(selected.first_seen_at).toLocaleString("vi-VN")}</dd>
          </div>
          <div className="rounded-xl border border-border p-3">
            <dt className="text-xs text-muted-foreground">Gần nhất</dt>
            <dd className="mt-1 font-medium">{new Date(selected.last_seen_at).toLocaleString("vi-VN")}</dd>
          </div>
        </dl>
      </section>

      <details className="group rounded-xl border border-border p-4">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold">
          Dữ liệu kỹ thuật
          <span className="flex items-center gap-2 text-xs font-normal text-muted-foreground">
            {presentation.evidenceLabel}
            <ChevronDown className="size-4 transition-transform group-open:rotate-180" />
          </span>
        </summary>
        <div className="mt-4 space-y-4 border-t border-border pt-4 text-xs">
          <div>
            <h4 className="font-semibold">Mã bằng chứng</h4>
            <ul className="mt-2 space-y-1">
              {selected.evidence_refs.map((ref) => <li key={ref} className="break-all font-mono text-[10px]">{ref}</li>)}
              {selected.evidence_refs.length === 0 && <li className="text-muted-foreground">API không trả mã bằng chứng.</li>}
            </ul>
          </div>
          {selected.url_fingerprints.length > 0 && (
            <div>
              <h4 className="font-semibold">Fingerprint URL đã tối thiểu hóa</h4>
              <ul className="mt-2 space-y-1">
                {selected.url_fingerprints.map((value) => <li key={value} className="break-all font-mono text-[10px]">{value}</li>)}
              </ul>
            </div>
          )}
          {selected.lexical_features.length > 0 && (
            <div>
              <h4 className="font-semibold">Đặc trưng URL</h4>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {selected.lexical_features.map((value) => <li key={value} className="rounded bg-muted px-2 py-1 font-mono text-[10px]">{value}</li>)}
              </ul>
            </div>
          )}
          <dl className="space-y-1 font-mono text-[10px] text-muted-foreground">
            <div><dt className="inline">Memory ID: </dt><dd className="inline break-all">{selected.memory_id}</dd></div>
            <div><dt className="inline">Analysis ID: </dt><dd className="inline break-all">{selected.analysis_id}</dd></div>
            <div><dt className="inline">Phiên bản: </dt><dd className="inline">{selected.risk_policy_version} · {selected.fingerprint_version}</dd></div>
          </dl>
        </div>
      </details>

      <section aria-labelledby="memory-correction-heading" className="rounded-xl border border-border p-4">
        <h4 id="memory-correction-heading" className="text-sm font-semibold">Đánh giá của người duyệt</h4>
        <label htmlFor="memory-verdict" className="mt-3 block text-xs font-semibold">Kết luận của người duyệt</label>
        <select id="memory-verdict" aria-label="Kết luận của người duyệt" value={verdict} onChange={(event) => setVerdict(event.target.value as SecurityMemoryReviewedVerdictV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">
          {["suspicious", "malicious", "safe", "false_positive"].map((item) => <option key={item} value={item}>{verdictLabel(item)}</option>)}
        </select>
        <label htmlFor="memory-note" className="mt-3 block text-xs font-semibold">Ghi chú của người duyệt</label>
        <textarea
          id="memory-note"
          aria-label="Ghi chú của người duyệt"
          value={note}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Nêu dữ liệu đã đối chiếu và lý do đưa ra kết luận."
          className="mt-1 min-h-24 w-full rounded-xl border border-border bg-background p-3 text-sm"
        />
        <button type="button" disabled={!note.trim() || busy} onClick={() => void onCorrect(selected, verdict, note.trim()).then(() => setNote(""))} className="mt-3 w-full rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45">
          {busy ? "Đang lưu…" : "Lưu kết luận"}
        </button>
      </section>

      <section>
        <h4 className="micro-label">Lịch sử đánh giá</h4>
        <div className="mt-2 space-y-2">
          {audit.map((record) => (
            <article key={record.audit_id} className="rounded-xl border border-border p-3 text-xs">
              <strong>{verdictLabel(record.previous_verdict)} → {verdictLabel(record.verdict)}</strong>
              <p className="mt-1 text-muted-foreground">{record.reviewer_id}: {record.note}</p>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                {record.risk_policy_version} · {record.fingerprint_version} · {new Date(record.occurred_at).toLocaleString("vi-VN")}
              </p>
              <p className="mt-1 text-[10px] text-muted-foreground">Mã bằng chứng: {record.evidence_refs.length}</p>
            </article>
          ))}
          {audit.length === 0 && <p className="text-xs text-muted-foreground">Chưa có lịch sử đánh giá.</p>}
        </div>
      </section>
    </div>
  );
}

export function SecurityMemoryRegistry({ page, query, selected, audit, loading, detailLoading, busy, error, onQueryChange, onSelect, onCorrect, onRetry }: {
  page: SecurityMemoryPageV4 | null;
  query: SecurityMemoryQueryState;
  selected: SecurityMemoryRecordV4 | null;
  audit: SecurityMemoryAuditRecordV4[];
  loading: boolean;
  detailLoading: boolean;
  busy: boolean;
  error: string | null;
  onQueryChange: (query: SecurityMemoryQueryState) => void;
  onSelect: (record: SecurityMemoryRecordV4) => Promise<void>;
  onCorrect: (record: SecurityMemoryRecordV4, verdict: SecurityMemoryReviewedVerdictV4, note: string) => Promise<void>;
  onRetry: () => void;
}) {
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 10)));
  return (
    <section aria-labelledby="memory-heading" className="space-y-4">
      <header>
        <p className="micro-label">Security Memory v4</p>
        <h2 id="memory-heading" className="mt-1 text-xl font-bold">Đánh giá lại bản ghi bảo mật</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Đối chiếu dữ liệu của lần check và lưu kết luận cùng lịch sử đánh giá.
        </p>
      </header>
      <div className="grid gap-2 lg:grid-cols-[1fr_auto_auto]">
        <label className="relative">
          <span className="sr-only">Tìm Security Memory</span>
          <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
          <input aria-label="Tìm Security Memory" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" placeholder="Thương hiệu hoặc domain…" />
        </label>
        <select aria-label="Lọc Memory theo mức rủi ro" value={query.risk} onChange={(event) => onQueryChange({ ...query, risk: event.target.value as SecurityMemoryQueryState["risk"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm">
          <option value="all">Tất cả mức rủi ro</option>
          {["SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS", "INSUFFICIENT_EVIDENCE"].map((item) => <option key={item} value={item}>{riskLabel(item)}</option>)}
        </select>
        <select aria-label="Lọc Memory theo kết luận" value={query.verdict} onChange={(event) => onQueryChange({ ...query, verdict: event.target.value as SecurityMemoryQueryState["verdict"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm">
          <option value="all">Tất cả kết luận</option>
          {["unreviewed", "suspicious", "malicious", "safe", "false_positive"].map((item) => <option key={item} value={item}>{verdictLabel(item)}</option>)}
        </select>
      </div>
      {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
      <div className="grid gap-4 xl:grid-cols-[minmax(20rem,0.8fr)_minmax(24rem,1.2fr)]">
        <div className="space-y-2">
          {loading ? (
            <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải Security Memory…</p>
          ) : page?.items.map((record) => (
            <MemoryCard
              key={record.memory_id}
              record={record}
              selected={selected?.memory_id === record.memory_id}
              onSelect={() => void onSelect(record)}
            />
          ))}
          {!loading && page?.items.length === 0 && <p className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground">Không có bản ghi Memory phù hợp.</p>}
          <div className="flex items-center justify-end gap-2 text-xs">
            <button aria-label="Trang Memory trước" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>
            {query.page}/{lastPage}
            <button aria-label="Trang Memory sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button>
          </div>
        </div>
        <div className="rounded-2xl border border-border bg-card p-5">
          {!selected && !detailLoading && <div className="grid min-h-64 place-items-center text-center text-sm text-muted-foreground"><div><Database className="mx-auto mb-2 size-7" />Chọn một bản ghi để đánh giá.</div></div>}
          {detailLoading && <p role="status" className="py-16 text-center text-sm text-muted-foreground">Đang tải lịch sử đánh giá…</p>}
          {selected && !detailLoading && <MemoryDetail key={selected.memory_id} selected={selected} audit={audit} busy={busy} onCorrect={onCorrect} />}
        </div>
      </div>
    </section>
  );
}
