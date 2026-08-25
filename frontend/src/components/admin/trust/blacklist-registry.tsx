"use client";

import { useCallback, useEffect, useState } from "react";
import { Ban, ChevronDown, FileClock, Plus, Search, ShieldAlert } from "lucide-react";

import { ApiError } from "@/lib/api/api-error";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import { securityLabel, statusLabel } from "@/lib/presentation/security-labels";
import type {
  SecurityBlacklistAuditRecordV4,
  SecurityBlacklistLifecycleV4,
  SecurityBlacklistRecordV4,
} from "@/types/generated/api-v4";

const PAGE_SIZE = 10;

function canonicalDomain(value: string): string | null {
  const raw = value.trim();
  if (!raw || raw.includes("://") || raw.includes("/") || raw.includes("@")) return null;
  try {
    const domain = new URL(`https://${raw}`).hostname.toLowerCase().replace(/\.$/, "");
    return domain.includes(".") ? domain : null;
  } catch {
    return null;
  }
}

function lifecycleLabel(value: SecurityBlacklistLifecycleV4): string {
  return value === "active" ? "Đang chặn" : "Đã vô hiệu hóa";
}

function operationError(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "Domain đã thay đổi trạng thái hoặc có proposal trùng. Dữ liệu đã được tải lại; hệ thống không tự gửi lại quyết định.";
  }
  return error instanceof Error ? error.message : "Không thể hoàn tất thao tác danh sách chặn.";
}

export function BlacklistRegistry({ api }: { api: SecurityAnalysisApi }) {
  const [query, setQuery] = useState({ q: "", lifecycle: "all" as "all" | SecurityBlacklistLifecycleV4, page: 1 });
  const [items, setItems] = useState<SecurityBlacklistRecordV4[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [domain, setDomain] = useState("");
  const [reason, setReason] = useState("");
  const [provenance, setProvenance] = useState("");
  const [evidence, setEvidence] = useState("");
  const [pendingDomain, setPendingDomain] = useState<string | null>(null);
  const [pendingDisable, setPendingDisable] = useState<SecurityBlacklistRecordV4 | null>(null);
  const [selected, setSelected] = useState<SecurityBlacklistRecordV4 | null>(null);
  const [audit, setAudit] = useState<SecurityBlacklistAuditRecordV4[]>([]);

  const load = useCallback(async (preserveError = false) => {
    setLoading(true);
    try {
      if (!api.pageBlacklist) throw new Error("Client hiện tại chưa hỗ trợ API danh sách chặn v4.");
      const page = await api.pageBlacklist({
        limit: PAGE_SIZE,
        offset: (query.page - 1) * PAGE_SIZE,
        ...(query.q.trim() ? { q: query.q.trim() } : {}),
        ...(query.lifecycle !== "all" ? { lifecycle: query.lifecycle } : {}),
      });
      setItems(page.items); setTotal(page.total);
      if (!preserveError) setError(null);
    } catch (caught) {
      setError(operationError(caught));
    } finally {
      setLoading(false);
    }
  }, [api, query]);

  useEffect(() => { void Promise.resolve().then(() => load()); }, [load]);

  const prepareCreate = () => {
    const canonical = canonicalDomain(domain);
    if (!canonical || !reason.trim() || !provenance.trim() || !evidence.trim()) {
      setError("Hãy nhập domain hợp lệ, lý do, provenance và ít nhất một nguồn bằng chứng.");
      return;
    }
    setError(null); setPendingDomain(canonical);
  };

  const executeCreate = async () => {
    if (!pendingDomain || busy) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      if (!api.proposeBlacklist || !api.decideBlacklistAction) throw new Error("Ứng dụng chưa hỗ trợ hành động chặn có bước duyệt.");
      const evidenceRefs = evidence.split(",").map((item) => item.trim()).filter(Boolean);
      const proposal = await api.proposeBlacklist({
        canonical_domain: pendingDomain,
        reason: reason.trim(),
        provenance: provenance.trim(),
        evidence_refs: evidenceRefs,
      });
      const result = await api.decideBlacklistAction(proposal.action_id, {
        decision: "approved",
        note: reason.trim(),
      });
      if (result.status !== "executed") {
        throw new Error(result.execution_error
          ? `Thực thi thất bại: ${result.execution_error}`
          : `Hành động kết thúc với trạng thái ${statusLabel(result.status)}; domain chưa được báo là đã chặn.`);
      }
      setNotice(`Đã chặn ${pendingDomain} sau khi proposal được duyệt và thực thi.`);
      setPendingDomain(null); setFormOpen(false); setDomain(""); setReason(""); setProvenance(""); setEvidence("");
      await load();
    } catch (caught) {
      setError(operationError(caught));
      await load(true);
    } finally {
      setBusy(false);
    }
  };

  const executeDisable = async () => {
    if (!pendingDisable || busy) return;
    setBusy(true); setError(null); setNotice(null);
    try {
      if (!api.proposeDisableBlacklist || !api.decideBlacklistAction) throw new Error("Client chưa hỗ trợ vô hiệu hóa danh sách chặn.");
      const proposal = await api.proposeDisableBlacklist(pendingDisable.blacklist_id, {
        reason: `Vô hiệu hóa ${pendingDisable.canonical_domain} sau khi rà soát.`,
        evidence_refs: pendingDisable.evidence_refs.length ? pendingDisable.evidence_refs : ["admin:disable-review"],
        provenance: `blacklist-record:${pendingDisable.blacklist_id}`,
      });
      const result = await api.decideBlacklistAction(proposal.action_id, {
        decision: "approved",
        note: `Admin xác nhận vô hiệu hóa ${pendingDisable.canonical_domain}.`,
      });
      if (result.status !== "executed") throw new Error(result.execution_error ?? `Hành động: ${statusLabel(result.status)}`);
      setNotice(`Đã vô hiệu hóa ${pendingDisable.canonical_domain}.`); setPendingDisable(null); await load();
    } catch (caught) {
      setError(operationError(caught)); await load(true);
    } finally {
      setBusy(false);
    }
  };

  const showAudit = async (record: SecurityBlacklistRecordV4) => {
    setSelected(record); setAudit([]); setError(null);
    try {
      if (!api.listBlacklistAudit) throw new Error("Client chưa hỗ trợ audit danh sách chặn.");
      setAudit(await api.listBlacklistAudit(record.blacklist_id));
    }
    catch (caught) { setError(operationError(caught)); }
  };

  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return (
    <section aria-labelledby="blacklist-heading" className="space-y-4">
      <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div><h2 id="blacklist-heading" className="text-xl font-bold">Domain đang chặn</h2><p className="mt-1 text-xs text-muted-foreground">Mỗi thao tác thêm hoặc vô hiệu hóa đều tạo đề xuất, quyết định của người duyệt và lịch sử bất biến.</p></div>
        <button type="button" onClick={() => setFormOpen((value) => !value)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Thêm domain cần chặn</button>
      </header>

      {formOpen && <div className="grid gap-3 rounded-2xl border border-border bg-card p-4 md:grid-cols-2">
        <label className="text-xs font-semibold">Domain<input aria-label="Domain cần chặn" value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="example.test" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label>
        <label className="text-xs font-semibold">Nguồn xác minh (provenance)<input aria-label="Provenance danh sách chặn" value={provenance} onChange={(event) => setProvenance(event.target.value)} placeholder="Báo cáo hoặc nguồn rà soát" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label>
        <label className="text-xs font-semibold md:col-span-2">Lý do<textarea aria-label="Lý do chặn" value={reason} onChange={(event) => setReason(event.target.value)} className="mt-1 min-h-20 w-full rounded-xl border border-border bg-background p-3 text-sm" /></label>
        <label className="text-xs font-semibold md:col-span-2">Nguồn bằng chứng, phân cách bằng dấu phẩy<input aria-label="Nguồn bằng chứng chặn" value={evidence} onChange={(event) => setEvidence(event.target.value)} placeholder="evidence:..., report:..." className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label>
        <button type="button" onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground md:col-span-2">Xem trước domain chuẩn hóa</button>
      </div>}

      <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tìm domain chặn</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tìm domain chặn" value={query.q} onChange={(event) => setQuery({ ...query, q: event.target.value, page: 1 })} placeholder="Tìm domain…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Lọc trạng thái danh sách chặn" value={query.lifecycle} onChange={(event) => setQuery({ ...query, lifecycle: event.target.value as typeof query.lifecycle, page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">Tất cả trạng thái</option><option value="active">Đang chặn</option><option value="disabled">Đã vô hiệu hóa</option></select></div>
      {error && <div role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={() => void load()} className="ml-2 underline">Tải lại</button></div>}
      {notice && <p role="status" className="rounded-xl bg-emerald-500/10 p-3 text-sm text-emerald-700 dark:text-emerald-300">{notice}</p>}
      {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải danh sách chặn…</p> : <div className="grid gap-3 lg:grid-cols-2">{items.map((record) => <article key={record.blacklist_id} className="rounded-2xl border border-border bg-card p-4"><div className="flex items-start justify-between gap-3"><div><p className="break-all font-mono text-sm font-semibold">{record.canonical_domain}</p><p className="mt-1 text-xs text-muted-foreground">{record.reason}</p></div><span className="rounded-full bg-muted px-2 py-1 text-[10px] font-bold">{lifecycleLabel(record.lifecycle)}</span></div><dl className="mt-3 grid gap-1 text-xs text-muted-foreground"><div><dt className="inline font-semibold text-foreground">Nguồn xác minh: </dt><dd className="inline">{record.provenance}</dd></div><div><dt className="inline font-semibold text-foreground">Bằng chứng: </dt><dd className="inline">{record.evidence_refs.length}</dd></div><div><dt className="inline font-semibold text-foreground">Cập nhật: </dt><dd className="inline">{new Date(record.updated_at).toLocaleString("vi-VN")}</dd></div></dl><div className="mt-4 flex gap-2"><button type="button" onClick={() => void showAudit(record)} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-border px-3 py-2 text-xs font-semibold"><FileClock className="size-4" />Xem lịch sử</button>{record.lifecycle === "active" && <button type="button" onClick={() => setPendingDisable(record)} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-rose-500/30 px-3 py-2 text-xs font-semibold text-rose-700"><Ban className="size-4" />Vô hiệu hóa</button>}</div></article>)}{items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">Không có domain phù hợp.</p>}</div>}
      <div className="flex items-center justify-between text-xs text-muted-foreground"><span>Trang {query.page}/{lastPage} · {total} mục</span><div className="flex gap-2"><button type="button" disabled={query.page <= 1} onClick={() => setQuery({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-3 py-1.5 disabled:opacity-40">Trước</button><button type="button" disabled={query.page >= lastPage} onClick={() => setQuery({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-3 py-1.5 disabled:opacity-40">Sau</button></div></div>

      {pendingDomain && <div role="dialog" aria-modal="true" aria-labelledby="confirm-blacklist-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><ShieldAlert className="size-6 text-rose-600" /><h3 id="confirm-blacklist-create" className="mt-2 text-lg font-bold">Xác nhận tạo và duyệt đề xuất</h3><p className="mt-2 text-sm">Domain chuẩn hóa:</p><p className="mt-1 break-all rounded-xl bg-muted p-3 font-mono font-semibold">{pendingDomain}</p><p className="mt-3 text-xs leading-5 text-muted-foreground">Xác nhận sẽ tạo đề xuất, sau đó gửi một quyết định duyệt. Chỉ trạng thái <code>executed</code> mới được báo thành công.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDomain(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void executeCreate()} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">{busy ? "Đang thực thi…" : "Xác nhận chặn"}</button></div></div></div>}
      {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-blacklist-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-blacklist-disable" className="text-lg font-bold">Xác nhận vô hiệu hóa</h3><p className="mt-2 break-all font-mono text-sm">{pendingDisable.canonical_domain}</p><p className="mt-2 text-xs text-muted-foreground">Thao tác này cũng đi qua đề xuất và quyết định có người duyệt; lịch sử không bị xóa.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void executeDisable()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Xác nhận vô hiệu hóa</button></div></div></div>}
      {selected && <div role="dialog" aria-modal="true" aria-labelledby="blacklist-audit-title" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="max-h-[80vh] w-full max-w-xl overflow-y-auto rounded-2xl border border-border bg-card p-5 shadow-2xl"><div className="flex items-start justify-between"><div><p className="micro-label">Lịch sử bất biến</p><h3 id="blacklist-audit-title" className="mt-1 break-all font-mono font-bold">{selected.canonical_domain}</h3></div><button type="button" onClick={() => setSelected(null)} aria-label="Đóng lịch sử" className="rounded-lg border border-border p-2"><ChevronDown className="size-4" /></button></div><div className="mt-4 space-y-3">{audit.map((item) => <article key={item.decision_id} className="rounded-xl border border-border p-3 text-xs"><strong>{securityLabel(item.action)} · {statusLabel(item.status)}</strong><p className="mt-1">{item.note}</p><p className="mt-1 text-muted-foreground">{new Date(item.decided_at).toLocaleString("vi-VN")} · {item.evidence_refs.join(", ") || "Không có mã bằng chứng"}</p></article>)}{audit.length === 0 && <p className="text-sm text-muted-foreground">Chưa có lịch sử hoặc đang tải.</p>}</div></div></div>}
    </section>
  );
}
