import { useState } from "react";
import { BadgeCheck, Ban, ChevronDown, Plus, Search } from "lucide-react";

import { lifecycleLabel, securityLabel } from "@/lib/presentation/security-labels";
import type { SecurityAdminAuditEventV4, TrustLifecycleV4, WhitelistCreateRequestV4, WhitelistPageV4, WhitelistRecordV4, WhitelistScopeV4 } from "@/types/generated/api-v4";

export interface WhitelistRegistryQuery {
  q: string;
  lifecycle: "all" | TrustLifecycleV4;
  page: number;
}

export function WhitelistRegistry({ page, query, loading, busy, error, onQueryChange, onCreate, onDisable, onAudit, onRetry }: {
  page: WhitelistPageV4 | null;
  query: WhitelistRegistryQuery;
  loading: boolean;
  busy: boolean;
  error: string | null;
  onQueryChange: (query: WhitelistRegistryQuery) => void;
  onCreate: (request: WhitelistCreateRequestV4) => Promise<void>;
  onDisable: (record: WhitelistRecordV4) => Promise<void>;
  onAudit: (record: WhitelistRecordV4) => Promise<SecurityAdminAuditEventV4[]>;
  onRetry: () => void;
}) {
  const [formOpen, setFormOpen] = useState(false);
  const [indicator, setIndicator] = useState("");
  const [scope, setScope] = useState<WhitelistScopeV4>("domain");
  const [provenance, setProvenance] = useState("");
  const [policyVersion, setPolicyVersion] = useState("whitelist-v1");
  const [effectiveFrom, setEffectiveFrom] = useState("");
  const [effectiveUntil, setEffectiveUntil] = useState("");
  const [pendingCreate, setPendingCreate] = useState<WhitelistCreateRequestV4 | null>(null);
  const [pendingDisable, setPendingDisable] = useState<WhitelistRecordV4 | null>(null);
  const [selectedAudit, setSelectedAudit] = useState<WhitelistRecordV4 | null>(null);
  const [audit, setAudit] = useState<SecurityAdminAuditEventV4[]>([]);

  const prepareCreate = () => {
    if (!indicator.trim() || !provenance.trim() || !effectiveFrom) return;
    const request: WhitelistCreateRequestV4 = {
      indicator: indicator.trim(), scope, provenance: provenance.trim(),
      policy_version: policyVersion.trim() || "whitelist-v1",
      effective_from: new Date(effectiveFrom).toISOString(),
      effective_until: effectiveUntil ? new Date(effectiveUntil).toISOString() : null,
    };
    if (request.effective_until && request.effective_until <= request.effective_from) return;
    setPendingCreate(request);
  };

  const confirmCreate = async () => {
    if (!pendingCreate) return;
    await onCreate(pendingCreate);
    setPendingCreate(null); setFormOpen(false); setIndicator(""); setProvenance(""); setEffectiveFrom(""); setEffectiveUntil("");
  };
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 10)));

  return (
    <section aria-labelledby="whitelist-heading" className="space-y-4">
      <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><h2 id="whitelist-heading" className="text-xl font-bold">Ngoại lệ tin cậy đã duyệt</h2><p className="mt-1 text-xs text-muted-foreground">Ngoại lệ không tự chứng minh danh tính người gửi, quyền sở hữu tài nguyên hoặc tính an toàn khi có bằng chứng xung đột.</p></div><button type="button" onClick={() => setFormOpen((value) => !value)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Thêm ngoại lệ</button></header>
      {formOpen && <div className="grid gap-3 rounded-2xl border border-border bg-card p-4 md:grid-cols-2"><label className="text-xs font-semibold">Giá trị ngoại lệ<input aria-label="Giá trị ngoại lệ tin cậy" value={indicator} onChange={(event) => setIndicator(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Phạm vi<select aria-label="Phạm vi ngoại lệ tin cậy" value={scope} onChange={(event) => setScope(event.target.value as WhitelistScopeV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="domain">Domain</option><option value="url">URL cụ thể</option><option value="contact">Thông tin liên hệ</option></select></label><label className="text-xs font-semibold md:col-span-2">Nguồn xác minh/provenance<textarea aria-label="Provenance ngoại lệ tin cậy" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-20 w-full rounded-xl border border-border bg-background p-3 text-sm" /></label><label className="text-xs font-semibold md:col-span-2">Phiên bản chính sách<input aria-label="Phiên bản chính sách ngoại lệ" value={policyVersion} onChange={(event) => setPolicyVersion(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Hiệu lực từ<input aria-label="Thời điểm bắt đầu hiệu lực" type="datetime-local" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Hiệu lực đến (không bắt buộc)<input aria-label="Thời điểm kết thúc hiệu lực" type="datetime-local" value={effectiveUntil} onChange={(event) => setEffectiveUntil(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><button type="button" disabled={busy || !indicator.trim() || !provenance.trim() || !effectiveFrom} onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45 md:col-span-2">Xem lại yêu cầu tạo</button></div>}
      <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tìm ngoại lệ tin cậy</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tìm ngoại lệ tin cậy" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} placeholder="Tìm giá trị ngoại lệ…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Lọc trạng thái ngoại lệ" value={query.lifecycle} onChange={(event) => onQueryChange({ ...query, lifecycle: event.target.value as WhitelistRegistryQuery["lifecycle"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">Tất cả trạng thái</option><option value="active">Đang hiệu lực</option><option value="disabled">Đã vô hiệu hóa</option></select></div>
      {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
      {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải danh sách tin cậy…</p> : <div className="grid gap-3 lg:grid-cols-2">{page?.items.map((record) => <WhitelistCard key={record.whitelist_id} record={record} onDisable={setPendingDisable} onAudit={() => { setSelectedAudit(record); setAudit([]); void onAudit(record).then(setAudit); }} />)}{page?.items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">Không có ngoại lệ phù hợp.</p>}</div>}
      <div className="flex items-center justify-end gap-2 text-xs"><button aria-label="Trang danh sách tin cậy trước" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{query.page}/{lastPage}<button aria-label="Trang danh sách tin cậy sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
      {pendingCreate && <div role="dialog" aria-modal="true" aria-labelledby="confirm-whitelist-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><BadgeCheck className="size-6 text-primary" /><h3 id="confirm-whitelist-create" className="mt-2 text-lg font-bold">Xác nhận tạo ngoại lệ tin cậy</h3><p className="mt-2 break-all text-sm">{pendingCreate.scope}: {pendingCreate.indicator}</p><p className="mt-1 text-xs text-muted-foreground">{pendingCreate.provenance}</p><p className="mt-2 text-xs text-muted-foreground">Hiệu lực {new Date(pendingCreate.effective_from).toLocaleString("vi-VN")} → {pendingCreate.effective_until ? new Date(pendingCreate.effective_until).toLocaleString("vi-VN") : "không thời hạn"}</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingCreate(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void confirmCreate()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Xác nhận tạo</button></div></div></div>}
      {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-whitelist-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-whitelist-disable" className="break-all text-lg font-bold">Vô hiệu hóa {pendingDisable.indicator}?</h3><p className="mt-2 text-sm text-muted-foreground">Record không bị xóa; lifecycle và lịch sử duyệt vẫn được giữ lại.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void onDisable(pendingDisable).then(() => setPendingDisable(null))} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">Xác nhận vô hiệu hóa</button></div></div></div>}
      {selectedAudit && <div role="dialog" aria-modal="true" aria-labelledby="whitelist-audit-title" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="max-h-[80vh] w-full max-w-xl overflow-y-auto rounded-2xl border border-border bg-card p-5 shadow-2xl"><div className="flex justify-between gap-3"><div><p className="micro-label">Lịch sử bất biến</p><h3 id="whitelist-audit-title" className="break-all font-semibold">{selectedAudit.indicator}</h3></div><button type="button" aria-label="Đóng lịch sử tin cậy" onClick={() => setSelectedAudit(null)}>Đóng</button></div><div className="mt-4 space-y-2">{audit.map((item) => <article key={item.audit_id} className="rounded-xl border border-border p-3 text-xs"><strong>{securityLabel(item.action)}</strong><p>{item.note ?? "Không có ghi chú"}</p><p className="text-muted-foreground">{item.actor_id} · {new Date(item.occurred_at).toLocaleString("vi-VN")}</p></article>)}{audit.length === 0 && <p className="text-sm text-muted-foreground">Chưa có lịch sử hoặc đang tải.</p>}</div></div></div>}
    </section>
  );
}

function WhitelistCard({ record, onDisable, onAudit }: { record: WhitelistRecordV4; onDisable: (record: WhitelistRecordV4) => void; onAudit: () => void }) {
  return <article className="rounded-2xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{lifecycleLabel(record.lifecycle)}</span><span className="rounded-full border border-primary/20 bg-primary/8 px-2 py-0.5 text-[10px] font-bold uppercase text-primary">{securityLabel(record.scope)}</span><h3 className="break-all font-semibold">{record.indicator}</h3></div><details className="group mt-3 border-t border-border pt-2"><summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">Nguồn và hiệu lực <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" /></summary><div className="mt-2 space-y-2 text-xs text-muted-foreground"><p className="leading-5">{record.provenance}</p><dl className="grid grid-cols-2 gap-2 text-[10px]"><div><dt>Chính sách</dt><dd>{record.policy_version}</dd></div><div><dt>Người duyệt</dt><dd>{record.reviewer_id}</dd></div><div><dt>Hiệu lực</dt><dd>{new Date(record.effective_from).toLocaleString("vi-VN")}</dd></div><div><dt>Đến</dt><dd>{record.effective_until ? new Date(record.effective_until).toLocaleString("vi-VN") : "không thời hạn"}</dd></div></dl></div></details><div className="mt-3 flex gap-2"><button type="button" onClick={onAudit} className="rounded-lg border border-border px-3 py-1.5 text-xs font-semibold">Xem lịch sử</button>{record.lifecycle === "active" && <button type="button" onClick={() => onDisable(record)} className="inline-flex items-center gap-2 rounded-lg border border-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300"><Ban className="size-3.5" />Vô hiệu hóa</button>}</div></article>;
}
