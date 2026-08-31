"use client";

import { useState, type ReactNode } from "react";
import { BadgeCheck, Ban, ChevronDown, GitBranch, Plus, Search } from "lucide-react";

import type { BrandCreateRequestV4, BrandPageV4, BrandRecordV4, OfficialIdentityV4, TrustLifecycleV4 } from "@/types/generated/api-v4";
import { lifecycleLabel, securityLabel } from "@/lib/presentation/security-labels";

export interface TrustRegistryQuery { q: string; lifecycle: "all" | TrustLifecycleV4; page: number; }

function commaList(value: string) {
  return Array.from(new Set(value.split(",").map((item) => item.trim()).filter(Boolean)));
}

function toIso(value: string) { return new Date(value).toISOString(); }

function toLocal(value: string) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function normalizeDomainInput(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || !url.hostname) return null;
    return url.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
}

function normalizeVerificationSource(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || !url.hostname) return null;
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return null;
  }
}

export function BrandRegistry({ page, query, loading, busy, error, onQueryChange, onCreate, onCreateVersion, onDisable, onRetry }: {
  page: BrandPageV4 | null; query: TrustRegistryQuery; loading: boolean; busy: boolean; error: string | null;
  onQueryChange: (query: TrustRegistryQuery) => void;
  onCreate: (request: BrandCreateRequestV4) => Promise<void>;
  onCreateVersion: (brandId: string, request: BrandCreateRequestV4) => Promise<void>;
  onDisable: (record: BrandRecordV4) => Promise<void>; onRetry: () => void;
}) {
  const [formOpen, setFormOpen] = useState(false);
  const [versionOf, setVersionOf] = useState<BrandRecordV4 | null>(null);
  const [name, setName] = useState("");
  const [primarySite, setPrimarySite] = useState("");
  const [verificationSource, setVerificationSource] = useState("");
  const [aliases, setAliases] = useState("");
  const [contacts, setContacts] = useState("");
  const [additionalDomains, setAdditionalDomains] = useState("");
  const [effectiveUntil, setEffectiveUntil] = useState("");
  const [preservedIdentities, setPreservedIdentities] = useState<OfficialIdentityV4[]>([]);
  const [pendingCreate, setPendingCreate] = useState<BrandCreateRequestV4 | null>(null);
  const [pendingDisable, setPendingDisable] = useState<BrandRecordV4 | null>(null);

  const resetForm = () => {
    setFormOpen(false); setVersionOf(null); setName(""); setPrimarySite(""); setVerificationSource("");
    setAliases(""); setContacts(""); setAdditionalDomains(""); setEffectiveUntil("");
    setPreservedIdentities([]);
  };
  const openCreate = () => { resetForm(); setFormOpen(true); };
  const openVersion = (record: BrandRecordV4) => {
    setVersionOf(record); setName(record.name); setPrimarySite(record.official_domains[0] ?? "");
    setVerificationSource(record.provenance); setAliases(record.aliases.join(", "));
    setContacts(record.official_contacts.join(", ")); setAdditionalDomains(record.official_domains.slice(1).join(", "));
    setEffectiveUntil(record.effective_until ? toLocal(record.effective_until) : "");
    setPreservedIdentities(record.official_identities); setFormOpen(true);
  };

  const primaryDomain = normalizeDomainInput(primarySite);
  const sourceUrl = normalizeVerificationSource(verificationSource);
  const hasInvalidExpiry = Boolean(effectiveUntil && new Date(effectiveUntil) <= new Date());
  const valid = Boolean(name.trim() && primaryDomain && sourceUrl && !hasInvalidExpiry);
  const prepareCreate = () => {
    if (!valid || !primaryDomain || !sourceUrl) return;
    const officialDomains = Array.from(new Set([primaryDomain, ...commaList(additionalDomains)]));
    setPendingCreate({
      name: name.trim(), aliases: commaList(aliases), official_domains: officialDomains,
      official_identities: preservedIdentities, official_contacts: commaList(contacts), provenance: sourceUrl,
      ...(effectiveUntil ? { effective_until: toIso(effectiveUntil) } : {}),
    });
  };
  const confirmCreate = async () => {
    if (!pendingCreate) return;
    if (versionOf) await onCreateVersion(versionOf.brand_id, pendingCreate); else await onCreate(pendingCreate);
    setPendingCreate(null); resetForm();
  };
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 10)));

  return <section aria-labelledby="brand-registry-heading" className="space-y-4">
    <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><h2 id="brand-registry-heading" className="text-xl font-bold">Thương hiệu chính thức</h2><p className="mt-1 text-sm text-muted-foreground">Danh mục định danh đã được duyệt, không phải danh sách tin cậy.</p></div><button type="button" onClick={openCreate} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Thêm thương hiệu</button></header>

    {formOpen && <div className="space-y-4 rounded-2xl border border-border bg-card p-4">
      {versionOf && <p role="status" className="rounded-xl bg-primary/8 p-3 text-xs">Đang tạo phiên bản bất biến mới thay thế <code>{versionOf.brand_id}</code>. Bản ghi hiện tại không bị chỉnh sửa.</p>}
      <div className="grid gap-3 md:grid-cols-2">
        <Field label="Tên thương hiệu"><input required aria-label="Tên thương hiệu" value={name} onChange={(event) => setName(event.target.value)} placeholder="Ví dụ: Example Bank" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
        <Field label="Website hoặc domain chính thức"><input required aria-label="Website hoặc domain chính thức" value={primarySite} onChange={(event) => setPrimarySite(event.target.value)} placeholder="https://bank.example hoặc bank.example" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /><p className="mt-1 text-xs font-normal text-muted-foreground">Áp dụng cho domain này và các subdomain.</p></Field>
        <Field label="URL nguồn xác minh" className="md:col-span-2"><input required aria-label="URL nguồn xác minh thương hiệu" value={verificationSource} onChange={(event) => setVerificationSource(event.target.value)} placeholder="https://…" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /><p className="mt-1 text-xs font-normal text-muted-foreground">Nguồn để người duyệt khác có thể đối chiếu; query và fragment sẽ không được lưu.</p></Field>
      </div>
      {primarySite.trim() && !primaryDomain && <p role="alert" className="text-xs text-rose-700">Website/domain chưa hợp lệ.</p>}
      {verificationSource.trim() && !sourceUrl && <p role="alert" className="text-xs text-rose-700">Nguồn xác minh phải là URL HTTP hoặc HTTPS hợp lệ.</p>}
      <details className="rounded-xl border border-border p-3"><summary className="cursor-pointer text-sm font-semibold">Thông tin nâng cao <span className="font-normal text-muted-foreground">(không bắt buộc)</span></summary><p className="mt-2 text-xs text-muted-foreground">Chỉ thêm tên khác, domain, liên hệ hoặc thời hạn đặc biệt. Định danh như social profile hay URL đối tác được quản lý tại Duyệt định danh.</p><div className="mt-3 grid gap-3 md:grid-cols-2">
        <Field label="Tên gọi khác, phân cách bằng dấu phẩy"><input aria-label="Tên gọi khác của thương hiệu" value={aliases} onChange={(event) => setAliases(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
        <Field label="Thông tin liên hệ chính thức"><input aria-label="Thông tin liên hệ chính thức" value={contacts} onChange={(event) => setContacts(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
        <Field label="Domain chính thức bổ sung" className="md:col-span-2"><input aria-label="Domain chính thức bổ sung" value={additionalDomains} onChange={(event) => setAdditionalDomains(event.target.value)} placeholder="careers.bank.example, secure.bank.example" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
        {versionOf && preservedIdentities.length > 0 && <p className="rounded-xl bg-muted p-3 text-xs text-muted-foreground md:col-span-2">Phiên bản này giữ nguyên {preservedIdentities.length} định danh bổ sung hiện có. Quản lý định danh tại Duyệt định danh.</p>}
        <Field label="Hiệu lực đến" className="md:col-span-2"><input aria-label="Thời điểm thương hiệu kết thúc hiệu lực" type="datetime-local" value={effectiveUntil} onChange={(event) => setEffectiveUntil(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" />{hasInvalidExpiry && <p role="alert" className="mt-1 text-xs font-normal text-rose-700">Thời điểm kết thúc phải ở tương lai.</p>}</Field>
      </div></details>
      <div className="flex items-center justify-between gap-3"><p className="text-xs text-muted-foreground">Hệ thống tự chuẩn hóa domain, ghi người duyệt, phiên bản chính sách và thời điểm hiệu lực.</p><div className="flex shrink-0 gap-2"><button type="button" onClick={resetForm} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy || !valid} onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45">{versionOf ? "Xem lại phiên bản mới" : "Xem lại yêu cầu tạo"}</button></div></div>
    </div>}

    <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tìm thương hiệu</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tìm thương hiệu" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} placeholder="Tên, tên gọi khác hoặc domain…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Lọc thương hiệu theo vòng đời" value={query.lifecycle} onChange={(event) => onQueryChange({ ...query, lifecycle: event.target.value as TrustRegistryQuery["lifecycle"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">Tất cả trạng thái</option><option value="active">Đang hiệu lực</option><option value="disabled">Đã vô hiệu hóa</option></select></div>
    {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
    {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải danh sách thương hiệu…</p> : <div className="grid gap-3 lg:grid-cols-2">{page?.items.map((record) => <BrandCard key={record.brand_id} record={record} onVersion={openVersion} onDisable={setPendingDisable} />)}{page?.items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">Không có thương hiệu phù hợp.</p>}</div>}
    <div className="flex items-center justify-end gap-2 text-xs"><button aria-label="Brand page truoc" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{query.page}/{lastPage}<button aria-label="Brand page sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
    {pendingCreate && <ConfirmCreate request={pendingCreate} versionOf={versionOf} busy={busy} onCancel={() => setPendingCreate(null)} onConfirm={confirmCreate} />}
    {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-brand-disable" className="text-lg font-bold">Vô hiệu hóa {pendingDisable.name}?</h3><p className="mt-2 text-sm text-muted-foreground">Trạng thái vòng đời do API trả về và bản ghi vẫn giữ nguyên khả năng kiểm toán.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void onDisable(pendingDisable).then(() => setPendingDisable(null))} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">Xác nhận vô hiệu hóa</button></div></div></div>}
  </section>;
}

function Field({ label, className, children }: { label: string; className?: string; children: ReactNode }) { return <label className={`text-xs font-semibold ${className ?? ""}`}>{label}{children}</label>; }

function BrandCard({ record, onVersion, onDisable }: { record: BrandRecordV4; onVersion: (record: BrandRecordV4) => void; onDisable: (record: BrandRecordV4) => void }) {
  return <article className="rounded-2xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{lifecycleLabel(record.lifecycle)}</span><h3 className="font-semibold">{record.name}</h3></div><p className="mt-2 break-all text-sm text-muted-foreground">{record.official_domains.join(", ")}</p><p className="mt-2 text-xs text-muted-foreground">{record.official_domains.length} domain chính thức · {record.official_identities.length} định danh bổ sung · {record.official_contacts.length} liên hệ</p><details className="group mt-3 border-t border-border pt-2"><summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">Nguồn và lịch sử <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" /></summary><div className="mt-2 space-y-2 text-xs text-muted-foreground">{record.official_identities.length > 0 && <ul className="space-y-1">{record.official_identities.map((identity) => <li key={identity.identity_id ?? `${identity.identity_type}:${identity.canonical_value}`} className="break-all">{securityLabel(identity.identity_type)}: {identity.display_value}</li>)}</ul>}{record.official_contacts.length > 0 && <p>Liên hệ: {record.official_contacts.join(", ")}</p>}<p className="break-all leading-5">{record.provenance}</p><dl className="grid grid-cols-2 gap-2 text-[10px]"><div><dt>Hiệu lực</dt><dd>{new Date(record.effective_from).toLocaleString("vi-VN")}</dd></div><div><dt>Đến</dt><dd>{record.effective_until ? new Date(record.effective_until).toLocaleString("vi-VN") : "không thời hạn"}</dd></div><div><dt>Người duyệt</dt><dd>{record.reviewer_id}</dd></div><div><dt>Phiên bản</dt><dd className="break-all">{record.policy_version}</dd></div></dl></div></details>{record.lifecycle === "active" && <div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={() => onVersion(record)} className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><GitBranch className="size-3.5" />Tạo phiên bản mới</button><button type="button" onClick={() => onDisable(record)} className="inline-flex items-center gap-2 rounded-lg border border-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300"><Ban className="size-3.5" />Vô hiệu hóa</button></div>}</article>;
}

function ConfirmCreate({ request, versionOf, busy, onCancel, onConfirm }: { request: BrandCreateRequestV4; versionOf: BrandRecordV4 | null; busy: boolean; onCancel: () => void; onConfirm: () => Promise<void> }) {
  return <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><BadgeCheck className="size-6 text-primary" /><h3 id="confirm-brand-create" className="mt-2 text-lg font-bold">{versionOf ? "Xác nhận phiên bản thương hiệu mới" : "Xác nhận tạo thương hiệu"}</h3><p className="mt-2 text-sm">{request.name} · {request.official_domains.join(", ")}</p><p className="mt-1 text-xs text-muted-foreground">Domain chính áp dụng cho cả subdomain. Hệ thống sẽ ghi người duyệt và thời điểm hiệu lực hiện tại.</p>{versionOf && <p className="mt-2 text-xs text-muted-foreground">Thay thế {versionOf.brand_id}; bản ghi trước vẫn được giữ để kiểm toán.</p>}<p className="mt-3 break-all text-xs text-muted-foreground">Nguồn xác minh: {request.provenance}</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void onConfirm()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">{versionOf ? "Xác nhận phiên bản mới" : "Xác nhận tạo"}</button></div></div></div>;
}
