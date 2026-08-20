import { useState, type ReactNode } from "react";
import { BadgeCheck, Ban, GitBranch, Plus, Search, Trash2 } from "lucide-react";

import type { BrandCreateRequestV4, BrandPageV4, BrandRecordV4, OfficialIdentityTypeV4, OfficialIdentityV4, TrustLifecycleV4 } from "@/types/generated/api-v4";

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
    <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end"><div><p className="micro-label">V4 trust registry</p><h2 id="brand-registry-heading" className="mt-1 text-xl font-bold">Brand registry</h2><p className="mt-1 text-sm text-muted-foreground">Immutable official identities with provenance, effective interval and reviewer lifecycle.</p></div><button type="button" onClick={openCreate} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Create brand</button></header>

    {formOpen && <div className="grid gap-3 rounded-2xl border border-border bg-card p-4 md:grid-cols-2">
      {versionOf && <p role="status" className="rounded-xl bg-primary/8 p-3 text-xs md:col-span-2">Creating a new immutable version that supersedes <code>{versionOf.brand_id}</code>. The existing record is not edited.</p>}
      <Field label="Brand name"><input aria-label="Brand name" value={name} onChange={(event) => setName(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Aliases, comma-separated"><input aria-label="Brand aliases" value={aliases} onChange={(event) => setAliases(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Official domains"><input aria-label="Official domains" value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="example.com, bank.example" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Official contacts"><input aria-label="Official contacts" value={contacts} onChange={(event) => setContacts(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <fieldset className="grid gap-2 rounded-xl border border-border p-3 md:col-span-2 md:grid-cols-[12rem_1fr_1fr_auto]"><legend className="px-1 text-xs font-semibold">Official identities</legend>
        <select aria-label="Official identity type" value={identityType} onChange={(event) => setIdentityType(event.target.value as OfficialIdentityTypeV4)} className="rounded-lg border border-border bg-background px-2 py-2 text-xs">{identityTypes.map((type) => <option key={type}>{type}</option>)}</select>
        <input aria-label="Official identity value" value={identityValue} onChange={(event) => setIdentityValue(event.target.value)} placeholder="Canonical domain, URL or name" className="rounded-lg border border-border bg-background px-3 py-2 text-xs" />
        <input aria-label="Official identity entity" value={identityEntity} onChange={(event) => setIdentityEntity(event.target.value)} placeholder={name || "Entity name"} className="rounded-lg border border-border bg-background px-3 py-2 text-xs" />
        <button type="button" disabled={!identityValue.trim()} onClick={addIdentity} className="rounded-lg border border-border px-3 py-2 text-xs font-semibold disabled:opacity-40">Add identity</button>
        {identities.length > 0 && <ul className="space-y-2 md:col-span-4">{identities.map((identity, index) => <li key={`${identity.identity_type}:${identity.canonical_value}:${index}`} className="flex items-center justify-between gap-2 rounded-lg bg-muted p-2 text-xs"><span className="min-w-0 break-all"><strong>{identity.identity_type}</strong> · {identity.display_value}</span><button type="button" aria-label={`Remove identity ${identity.display_value}`} onClick={() => setIdentities((items) => items.filter((_, itemIndex) => itemIndex !== index))}><Trash2 className="size-3.5" /></button></li>)}</ul>}
      </fieldset>
      <label className="text-xs font-semibold md:col-span-2">Provenance<textarea aria-label="Brand provenance" value={provenance} onChange={(event) => setProvenance(event.target.value)} className="mt-1 min-h-20 w-full rounded-xl border border-border bg-background p-3 text-sm" /></label>
      <Field label="Policy version"><input aria-label="Brand policy version" value={policyVersion} onChange={(event) => setPolicyVersion(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field><span />
      <Field label="Effective from"><input aria-label="Brand effective from" type="datetime-local" value={effectiveFrom} onChange={(event) => setEffectiveFrom(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <Field label="Effective until (optional)"><input aria-label="Brand effective until" type="datetime-local" value={effectiveUntil} onChange={(event) => setEffectiveUntil(event.target.value)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></Field>
      <div className="flex justify-end gap-2 md:col-span-2"><button type="button" onClick={resetForm} className="rounded-xl px-4 py-2 text-sm">Cancel</button><button type="button" disabled={busy || !valid} onClick={prepareCreate} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45">{versionOf ? "Review new version" : "Review create request"}</button></div>
    </div>}

    <div className="grid gap-2 sm:grid-cols-[1fr_auto]"><label className="relative"><span className="sr-only">Tim brand</span><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><input aria-label="Tim brand" value={query.q} onChange={(event) => onQueryChange({ ...query, q: event.target.value, page: 1 })} placeholder="Name, alias or domain..." className="w-full rounded-xl border border-border bg-background py-2 pl-9 pr-3 text-sm" /></label><select aria-label="Loc brand theo lifecycle" value={query.lifecycle} onChange={(event) => onQueryChange({ ...query, lifecycle: event.target.value as TrustRegistryQuery["lifecycle"], page: 1 })} className="rounded-xl border border-border bg-background px-3 py-2 text-sm"><option value="all">all lifecycle</option><option value="active">active</option><option value="disabled">disabled</option></select></div>
    {error && <p role="alert" className="rounded-xl bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">{error}<button type="button" onClick={onRetry} className="ml-2 font-semibold underline">Thu lai</button></p>}
    {loading ? <p role="status" className="py-10 text-center text-sm text-muted-foreground">Dang tai brand registry...</p> : <div className="grid gap-3 lg:grid-cols-2">{page?.items.map((record) => <BrandCard key={record.brand_id} record={record} onVersion={openVersion} onDisable={setPendingDisable} />)}{page?.items.length === 0 && <p className="rounded-2xl border border-dashed border-border p-8 text-center text-sm text-muted-foreground lg:col-span-2">No brand record matches.</p>}</div>}
    <div className="flex items-center justify-end gap-2 text-xs"><button aria-label="Brand page truoc" disabled={query.page <= 1 || loading} onClick={() => onQueryChange({ ...query, page: query.page - 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">←</button>{query.page}/{lastPage}<button aria-label="Brand page sau" disabled={query.page >= lastPage || loading} onClick={() => onQueryChange({ ...query, page: query.page + 1 })} className="rounded-lg border border-border px-2 py-1 disabled:opacity-40">→</button></div>
    {pendingCreate && <ConfirmCreate request={pendingCreate} versionOf={versionOf} busy={busy} onCancel={() => setPendingCreate(null)} onConfirm={confirmCreate} />}
    {pendingDisable && <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-disable" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 shadow-2xl"><h3 id="confirm-brand-disable" className="text-lg font-bold">Disable {pendingDisable.name}?</h3><p className="mt-2 text-sm text-muted-foreground">Lifecycle state comes from the API and the record remains auditable.</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={() => setPendingDisable(null)} className="rounded-xl px-4 py-2 text-sm">Cancel</button><button type="button" disabled={busy} onClick={() => void onDisable(pendingDisable).then(() => setPendingDisable(null))} className="rounded-xl bg-rose-600 px-4 py-2 text-sm font-semibold text-white">Confirm disable</button></div></div></div>}
  </section>;
}

function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="text-xs font-semibold">{label}{children}</label>; }
function BrandCard({ record, onVersion, onDisable }: { record: BrandRecordV4; onVersion: (record: BrandRecordV4) => void; onDisable: (record: BrandRecordV4) => void }) {
  return <article className="rounded-2xl border border-border bg-card p-4"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full border border-border bg-muted px-2 py-0.5 text-[10px] font-bold uppercase">{record.lifecycle}</span><h3 className="font-semibold">{record.name}</h3><span className="text-[10px] text-muted-foreground">{record.policy_version}</span></div><p className="mt-2 break-all text-sm text-muted-foreground">{record.official_domains.join(", ")}</p>{record.official_identities.length > 0 && <ul className="mt-2 space-y-1 text-xs text-muted-foreground">{record.official_identities.map((identity) => <li key={identity.identity_id ?? `${identity.identity_type}:${identity.canonical_value}`} className="break-all">{identity.identity_type}: {identity.display_value}</li>)}</ul>}{record.official_contacts.length > 0 && <p className="mt-1 text-xs text-muted-foreground">Contacts: {record.official_contacts.join(", ")}</p>}<p className="mt-3 text-xs leading-5 text-muted-foreground">{record.provenance}</p><dl className="mt-3 grid grid-cols-2 gap-2 border-t border-border pt-3 text-[10px]"><div><dt className="text-muted-foreground">Effective</dt><dd>{new Date(record.effective_from).toLocaleString("vi-VN")}</dd></div><div><dt className="text-muted-foreground">Until</dt><dd>{record.effective_until ? new Date(record.effective_until).toLocaleString("vi-VN") : "open"}</dd></div><div><dt className="text-muted-foreground">Reviewer</dt><dd>{record.reviewer_id}</dd></div><div><dt className="text-muted-foreground">Supersedes</dt><dd className="break-all">{record.supersedes ?? "initial version"}</dd></div></dl>{record.lifecycle === "active" && <div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={() => onVersion(record)} className="inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold"><GitBranch className="size-3.5" />Create new version</button><button type="button" onClick={() => onDisable(record)} className="inline-flex items-center gap-2 rounded-lg border border-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-700 dark:text-rose-300"><Ban className="size-3.5" />Disable</button></div>}</article>;
}
function ConfirmCreate({ request, versionOf, busy, onCancel, onConfirm }: { request: BrandCreateRequestV4; versionOf: BrandRecordV4 | null; busy: boolean; onCancel: () => void; onConfirm: () => Promise<void> }) {
  return <div role="dialog" aria-modal="true" aria-labelledby="confirm-brand-create" className="fixed inset-0 z-50 grid place-items-center bg-background/80 p-4 backdrop-blur-sm"><div className="w-full max-w-lg rounded-2xl border border-border bg-card p-5 shadow-2xl"><BadgeCheck className="size-6 text-primary" /><h3 id="confirm-brand-create" className="mt-2 text-lg font-bold">{versionOf ? "Confirm new brand version" : "Confirm brand creation"}</h3><p className="mt-2 text-sm">{request.name} · {request.official_domains.join(", ")}</p>{versionOf && <p className="mt-2 text-xs text-muted-foreground">Supersedes {versionOf.brand_id}; the prior record remains auditable.</p>}<p className="mt-1 text-xs text-muted-foreground">{request.provenance}</p><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onCancel} className="rounded-xl px-4 py-2 text-sm">Cancel</button><button type="button" disabled={busy} onClick={() => void onConfirm()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">{versionOf ? "Confirm new version" : "Confirm create"}</button></div></div></div>;
}
