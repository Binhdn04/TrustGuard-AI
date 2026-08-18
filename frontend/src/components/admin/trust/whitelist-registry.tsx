import { useState } from "react";
import { BadgeCheck, Ban, Plus, Search } from "lucide-react";

import type { TrustLifecycleV4, WhitelistCreateRequestV4, WhitelistPageV4, WhitelistRecordV4, WhitelistScopeV4 } from "@/types/generated/api-v4";

export interface WhitelistRegistryQuery {
  q: string;
  lifecycle: "all" | TrustLifecycleV4;
  page: number;
}

export function WhitelistRegistry({ page, query, loading, busy, error, onQueryChange, onCreate, onDisable, onRetry }: {
  page: WhitelistPageV4 | null;
  query: WhitelistRegistryQuery;
  loading: boolean;
  busy: boolean;
  error: string | null;
  onQueryChange: (query: WhitelistRegistryQuery) => void;
  onCreate: (request: WhitelistCreateRequestV4) => Promise<void>;
  onDisable: (record: WhitelistRecordV4) => Promise<void>;
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
      <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><p className="micro-label">V4 trust registry</p><h2 id="whitelist-heading" className="mt-1 text-xl font-bold">Security whitelist</h2><p className="mt-1 text-sm text-muted-foreground">Reviewed domain, URL and contact exceptions with explicit lifecycle.</p></div><button type="button" onClick={() => setFormOpen((value) => !value)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Create whitelist</button></header>
      {formOpen && <div className="grid gap-3 rounded-2xl border border-border bg-card p-4 md:grid-cols-2"><label className="text-xs font-semibold">Indicator<input aria-label="Whitelist indicator" value={indicator} onChange={(event) => setIndicator(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Scope<select aria-label="Whitelist scope" value={scope} onChange={(event) => setScope(event.target.value as WhitelistScopeV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="domain">domain</option><option value="url">url</option><option value="contact">contact</option></select></label><label className="text-xs font-semibold md:col-span-2">Provenance<textarea aria-label="Whitelist provenance" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-20 w-full rounded-xl border border-border bg-background p-3 text-sm" /></label><label className="text-xs font-semibold md:col-span-2">Policy version<input aria-label="Whitelist policy version" value={policyVersion} onChange={(event) => setPolicyVersion(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Effective from<input aria-label="Whitelist effective from" type="datetime-local" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><label className="text-xs font-semibold">Effective until (optional)<input aria-label="Whitelist effective until" type="datetime-local" value={effectiveUntil} onChange={(event) => setEffectiveUntil(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label><button type="button" disabled={busy || !indicator.trim() || !provenance.trim() || !effectiveFrom} onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45 md:col-span-2">Review create request</button></div>}
      <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tìm whitelist</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tìm whitelist" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} placeholder="Indicator…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Lọc whitelist theo lifecycle" value={query.lifecycle} onChange={(event) => onQueryChange({ ...query, lifecycle: event.target.value as WhitelistRegistryQuery["lifecycle"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">all lifecycle</option><option value="active">active</option><option value="disabled">disabled</option></select></div>
      {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
      {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải whitelist…</p> : <div className="grid gap-3 lg:grid-cols-2">{page?.items.map((record) => <article key={record.whitelist_id} className="rounded-2xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{record.lifecycle}</span><span className="rounded-full border border-primary/20 bg-primary/8 px-2 py-0.5 text-[10px] font-bold uppercase text-primary">{record.scope}</span><h3 className="break-all font-semibold">{record.indicator}</h3></div><p className="mt-3 text-xs leading-5 text-muted-foreground">{record.provenance}</p><dl className="mt-3 grid grid-cols-2 gap-2 border-t border-border pt-3 text-[10px]"><div><dt className="text-muted-foreground">Policy</dt><dd>{record.policy_version}</dd></div><div><dt className="text-muted-foreground">Reviewer</dt><dd>{record.reviewer_id}</dd></div><div><dt className="text-muted-foreground">Effective</dt><dd>{new Date(record.effective_from).toLocaleString("vi-VN")}</dd></div><div><dt className="text-muted-foreground">Until</dt><dd>{record.effective_until ? new Date(record.effective_until).toLocaleString("vi-VN") : "open"}</dd></div></dl>{record.lifecycle === "active" && <button type="button" onClick={() => setPendingDisable(record)} className="mt-3 inline-flex items-center gap-2 rounded-lg border border-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300"><Ban className="size-3.5" />Disable</button>}</article>)}{page?.items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">No whitelist record matches.</p>}</div>}
      <div className="flex items-center justify-end gap-2 text-xs"><button aria-label="Whitelist page trước" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{query.page}/{lastPage}<button aria-label="Whitelist page sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
      {pendingCreate && <div role="dialog" aria-modal="true" aria-labelledby="confirm-whitelist-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><BadgeCheck className="size-6 text-primary" /><h3 id="confirm-whitelist-create" className="mt-2 text-lg font-bold">Confirm whitelist creation</h3><p className="mt-2 break-all text-sm">{pendingCreate.scope}: {pendingCreate.indicator}</p><p className="mt-1 text-xs text-muted-foreground">{pendingCreate.provenance}</p><p className="mt-2 text-xs text-muted-foreground">Effective {new Date(pendingCreate.effective_from).toLocaleString("vi-VN")} → {pendingCreate.effective_until ? new Date(pendingCreate.effective_until).toLocaleString("vi-VN") : "open"}</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingCreate(null)} className="rounded-xl px-4 py-2 text-sm">Cancel</button><button type="button" disabled={busy} onClick={() => void confirmCreate()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Confirm create</button></div></div></div>}
      {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-whitelist-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-whitelist-disable" className="break-all text-lg font-bold">Disable {pendingDisable.indicator}?</h3><p className="mt-2 text-sm text-muted-foreground">The API-returned lifecycle state remains visible and auditable.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Cancel</button><button type="button" disabled={busy} onClick={() => void onDisable(pendingDisable).then(() => setPendingDisable(null))} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">Confirm disable</button></div></div></div>}
    </section>
  );
}
