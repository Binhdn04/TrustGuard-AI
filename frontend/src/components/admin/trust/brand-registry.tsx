import { useState, type ReactNode } from "react";
import { BadgeCheck, Ban, ChevronDown, GitBranch, Plus, Search, Trash2 } from "lucide-react";

import type { BrandCreateRequestV4, BrandPageV4, BrandRecordV4, OfficialIdentityTypeV4, OfficialIdentityV4, TrustLifecycleV4 } from "@/types/generated/api-v4";
import { lifecycleLabel, securityLabel } from "@/lib/presentation/security-labels";

export interface TrustRegistryQuery { q: string; lifecycle: "all" | TrustLifecycleV4; page: number; }
const identityTypes: OfficialIdentityTypeV4[] = ["primary_website", "website", "domain", "careers_page", "social_profile", "sub_organization"];
function commaList(value: string) { return Array.from(new Set(value.split(",").map((item) => item.trim()).filter(Boolean))); }
function toIso(value: string) { return new Date(value).toISOString(); }
function toLocal(value: string) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
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
  const [name, setName] = useState(""); const [aliases, setAliases] = useState("");
  const [domains, setDomains] = useState(""); const [contacts, setContacts] = useState("");
  const [provenance, setProvenance] = useState(""); const [policyVersion, setPolicyVersion] = useState("brand-registry-v1");
  const [effectiveFrom, setEffectiveFrom] = useState(""); const [effectiveUntil, setEffectiveUntil] = useState("");
  const [identities, setIdentities] = useState<OfficialIdentityV4[]>([]);
  const [identityType, setIdentityType] = useState<OfficialIdentityTypeV4>("primary_website");
  const [identityValue, setIdentityValue] = useState(""); const [identityEntity, setIdentityEntity] = useState("");
  const [pendingCreate, setPendingCreate] = useState<BrandCreateRequestV4 | null>(null);
  const [pendingDisable, setPendingDisable] = useState<BrandRecordV4 | null>(null);

  const resetForm = () => {
    setFormOpen(false); setVersionOf(null); setName(""); setAliases(""); setDomains(""); setContacts("");
    setProvenance(""); setPolicyVersion("brand-registry-v1"); setEffectiveFrom(""); setEffectiveUntil("");
    setIdentities([]); setIdentityValue(""); setIdentityEntity("");
  };
  const openCreate = () => { resetForm(); setFormOpen(true); };
  const openVersion = (record: BrandRecordV4) => {
    setVersionOf(record); setName(record.name); setAliases(record.aliases.join(", ")); setDomains(record.official_domains.join(", "));
    setContacts(record.official_contacts.join(", ")); setProvenance(record.provenance); setPolicyVersion(record.policy_version);
    setEffectiveFrom(toLocal(new Date().toISOString())); setEffectiveUntil(record.effective_until ? toLocal(record.effective_until) : "");
    setIdentities(record.official_identities); setIdentityValue(""); setIdentityEntity(record.name); setFormOpen(true);
  };
  const addIdentity = () => {
    const value = identityValue.trim(); if (!value) return;
    setIdentities((items) => [...items, { identity_type: identityType, canonical_value: value, display_value: value, entity_name: identityEntity.trim() || name.trim() }]);
    setIdentityValue("");
  };
  const valid = Boolean(name.trim() && (commaList(domains).length || identities.length) && provenance.trim() && effectiveFrom);
  const prepareCreate = () => {
    if (!valid) return;
    const request: BrandCreateRequestV4 = {
      name: name.trim(), aliases: commaList(aliases), official_domains: commaList(domains), official_identities: identities,
      official_contacts: commaList(contacts), provenance: provenance.trim(), policy_version: policyVersion.trim() || "brand-registry-v1",
      effective_from: toIso(effectiveFrom), effective_until: effectiveUntil ? toIso(effectiveUntil) : null,
    };
    if (!request.effective_until || request.effective_until > request.effective_from) setPendingCreate(request);
  };
  const confirmCreate = async () => {
    if (!pendingCreate) return;
    if (versionOf) await onCreateVersion(versionOf.brand_id, pendingCreate); else await onCreate(pendingCreate);
    setPendingCreate(null); resetForm();
  };
  const lastPage = Math.max(1, Math.ceil((page?.total ?? 0) / (page?.limit ?? 10)));

  return <section aria-labelledby="brand-registry-heading" className="space-y-4">
    <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><h2 id="brand-registry-heading" className="text-xl font-bold">Thương hiệu chính thức</h2><button type="button" onClick={openCreate} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Thêm thương hiệu</button></header>

    {formOpen && <div className="grid gap-3 rounded-2xl border border-border bg-card p-4 md:grid-cols-2">
      {versionOf && <p role="status" className="rounded-xl bg-primary/8 p-3 text-xs md:col-span-2">Đang tạo phiên bản bất biến mới thay thế <code>{versionOf.brand_id}</code>. Bản ghi hiện tại không bị chỉnh sửa.</p>}
      <Field label="Tên thương hiệu"><input aria-label="Tên thương hiệu" value={name} onChange={(event) => setName(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Tên gọi khác, phân cách bằng dấu phẩy"><input aria-label="Tên gọi khác của thương hiệu" value={aliases} onChange={(event) => setAliases(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Domain chính thức"><input aria-label="Domain chính thức" value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="example.com, bank.example" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Thông tin liên hệ chính thức"><input aria-label="Thông tin liên hệ chính thức" value={contacts} onChange={(event) => setContacts(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <fieldset className="grid gap-2 rounded-xl border border-border p-3 md:col-span-2 md:grid-cols-[12rem_1fr_1fr_auto]"><legend className="px-1 text-xs font-semibold">Danh tính chính thức</legend>
        <select aria-label="Loại danh tính chính thức" value={identityType} onChange={(event) => setIdentityType(event.target.value as OfficialIdentityTypeV4)} className="rounded-lg border border-border bg-background px-2 py-2 text-xs">{identityTypes.map((type) => <option key={type} value={type}>{securityLabel(type)}</option>)}</select>
        <input aria-label="Giá trị danh tính chính thức" value={identityValue} onChange={(event) => setIdentityValue(event.target.value)} placeholder="Domain chuẩn hóa, URL hoặc tên" className="rounded-lg border border-border bg-background px-3 py-2 text-xs" />
        <input aria-label="Đơn vị của danh tính chính thức" value={identityEntity} onChange={(event) => setIdentityEntity(event.target.value)} placeholder={name || "Tên đơn vị"} className="rounded-lg border border-border bg-background px-3 py-2 text-xs" />
        <button type="button" disabled={!identityValue.trim()} onClick={addIdentity} className="rounded-lg border border-border px-3 py-2 text-xs font-semibold disabled:opacity-40">Thêm danh tính</button>
        {identities.length > 0 && <ul className="space-y-2 md:col-span-4">{identities.map((identity, index) => <li key={`${identity.identity_type}:${identity.canonical_value}:${index}`} className="flex items-center justify-between gap-2 rounded-lg bg-muted p-2 text-xs"><span className="min-w-0 break-all"><strong>{securityLabel(identity.identity_type)}</strong> · {identity.display_value}</span><button type="button" aria-label={`Xóa danh tính ${identity.display_value}`} onClick={() => setIdentities((items) => items.filter((_, itemIndex) => itemIndex !== index))}><Trash2 className="size-3.5" /></button></li>)}</ul>}
      </fieldset>
      <label className="text-xs font-semibold md:col-span-2">Nguồn xác minh<textarea aria-label="Nguồn xác minh thương hiệu" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-20 w-full rounded-xl border border-border bg-background p-3 text-sm" /></label>
      <Field label="Phiên bản chính sách"><input aria-label="Phiên bản chính sách thương hiệu" value={policyVersion} onChange={(event) => setPolicyVersion(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field><span />
      <Field label="Hiệu lực từ"><input aria-label="Thời điểm thương hiệu bắt đầu hiệu lực" type="datetime-local" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Hiệu lực đến (không bắt buộc)"><input aria-label="Thời điểm thương hiệu kết thúc hiệu lực" type="datetime-local" value={effectiveUntil} onChange={(event) => setEffectiveUntil(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <div className="flex justify-end gap-2 md:col-span-2"><button type="button" onClick={resetForm} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy || !valid} onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45">{versionOf ? "Xem lại phiên bản mới" : "Xem lại yêu cầu tạo"}</button></div>
    </div>}

    <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tìm thương hiệu</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tìm thương hiệu" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} placeholder="Tên, tên gọi khác hoặc domain…" className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Lọc thương hiệu theo vòng đời" value={query.lifecycle} onChange={(event) => onQueryChange({ ...query, lifecycle: event.target.value as TrustRegistryQuery["lifecycle"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">Tất cả trạng thái</option><option value="active">Đang hiệu lực</option><option value="disabled">Đã vô hiệu hóa</option></select></div>
    {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thử lại</button></p>}
    {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Đang tải danh sách thương hiệu…</p> : <div className="grid gap-3 lg:grid-cols-2">{page?.items.map((record) => <BrandCard key={record.brand_id} record={record} onVersion={openVersion} onDisable={setPendingDisable} />)}{page?.items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">Không có thương hiệu phù hợp.</p>}</div>}
    <div className="flex items-center justify-end gap-2 text-xs"><button aria-label="Brand page truoc" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{query.page}/{lastPage}<button aria-label="Brand page sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
    {pendingCreate && <ConfirmCreate request={pendingCreate} versionOf={versionOf} busy={busy} onCancel={() => setPendingCreate(null)} onConfirm={confirmCreate} />}
    {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-brand-disable" className="text-lg font-bold">Vô hiệu hóa {pendingDisable.name}?</h3><p className="mt-2 text-sm text-muted-foreground">Trạng thái vòng đời do API trả về và bản ghi vẫn giữ nguyên khả năng kiểm toán.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void onDisable(pendingDisable).then(() => setPendingDisable(null))} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">Xác nhận vô hiệu hóa</button></div></div></div>}
  </section>;
}

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="text-xs font-semibold">{label}{children}</label>; }
function BrandCard({ record, onVersion, onDisable }: { record: BrandRecordV4; onVersion: (record: BrandRecordV4) => void; onDisable: (record: BrandRecordV4) => void }) {
  return <article className="rounded-2xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{lifecycleLabel(record.lifecycle)}</span><h3 className="font-semibold">{record.name}</h3></div><p className="mt-2 break-all text-sm text-muted-foreground">{record.official_domains.join(", ")}</p>{record.official_identities.length > 0 && <p className="mt-2 text-xs text-muted-foreground">{record.official_identities.length} danh tính chính thức · {record.official_contacts.length} liên hệ</p>}<details className="group mt-3 border-t border-border pt-2"><summary className="flex cursor-pointer list-none items-center justify-between text-xs font-semibold text-muted-foreground">Nguồn và lịch sử <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" /></summary><div className="mt-2 space-y-2 text-xs text-muted-foreground">{record.official_identities.length > 0 && <ul className="space-y-1">{record.official_identities.map((identity) => <li key={identity.identity_id ?? `${identity.identity_type}:${identity.canonical_value}`} className="break-all">{securityLabel(identity.identity_type)}: {identity.display_value}</li>)}</ul>}{record.official_contacts.length > 0 && <p>Liên hệ: {record.official_contacts.join(", ")}</p>}<p className="leading-5">{record.provenance}</p><dl className="grid grid-cols-2 gap-2 text-[10px]"><div><dt>Hiệu lực</dt><dd>{new Date(record.effective_from).toLocaleString("vi-VN")}</dd></div><div><dt>Đến</dt><dd>{record.effective_until ? new Date(record.effective_until).toLocaleString("vi-VN") : "không thời hạn"}</dd></div><div><dt>Người duyệt</dt><dd>{record.reviewer_id}</dd></div><div><dt>Phiên bản</dt><dd className="break-all">{record.policy_version}</dd></div></dl></div></details>{record.lifecycle === "active" && <div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={() => onVersion(record)} className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><GitBranch className="size-3.5" />Tạo phiên bản mới</button><button type="button" onClick={() => onDisable(record)} className="inline-flex items-center gap-2 rounded-lg border border-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300"><Ban className="size-3.5" />Vô hiệu hóa</button></div>}</article>;
}
function ConfirmCreate({ request, versionOf, busy, onCancel, onConfirm }: { request: BrandCreateRequestV4; versionOf: BrandRecordV4 | null; busy: boolean; onCancel: () => void; onConfirm: () => Promise<void> }) {
  return <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><BadgeCheck className="size-6 text-primary" /><h3 id="confirm-brand-create" className="mt-2 text-lg font-bold">{versionOf ? "Xác nhận phiên bản thương hiệu mới" : "Xác nhận tạo thương hiệu"}</h3><p className="mt-2 text-sm">{request.name} · {request.official_domains.join(", ")}</p>{versionOf && <p className="mt-2 text-xs text-muted-foreground">Thay thế {versionOf.brand_id}; bản ghi trước vẫn được giữ để kiểm toán.</p>}<p className="mt-1 text-xs text-muted-foreground">{request.provenance}</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy} onClick={() => void onConfirm()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">{versionOf ? "Xác nhận phiên bản mới" : "Xác nhận tạo"}</button></div></div></div>;
}
