"use client";

import { useState } from "react";

import type {
  IdentityCandidateDecisionActionV4,
  IdentityCandidateDecisionRequestV4,
  IdentityCandidatePageV4,
  IdentityCandidateV4,
  IdentityRelationshipV4,
  OfficialIdentityTypeV4,
} from "@/types/generated/api-v4";

export type IdentityCandidateQuery = {
  entity: string; status: string; relationship: string; page: number;
};

type Props = {
  page: IdentityCandidatePageV4 | null; query: IdentityCandidateQuery; loading: boolean;
  busy: boolean; error: string | null; onQueryChange: (query: IdentityCandidateQuery) => void;
  onDecide: (candidate: IdentityCandidateV4, request: IdentityCandidateDecisionRequestV4) => Promise<void>;
  onRetry: () => void;
};

export function IdentityCandidateQueue({ page, query, loading, busy, error, onQueryChange, onDecide, onRetry }: Props) {
  const [review, setReview] = useState<{ candidate: IdentityCandidateV4; action: IdentityCandidateDecisionActionV4 } | null>(null);
  const [note, setNote] = useState("");
  const [targetBrandId, setTargetBrandId] = useState("");
  const [relationship, setRelationship] = useState<IdentityRelationshipV4 | "">("");
  const [identityType, setIdentityType] = useState<OfficialIdentityTypeV4 | "">("");
  const startReview = (candidate: IdentityCandidateV4, action: IdentityCandidateDecisionActionV4) => {
    setReview({ candidate, action }); setNote(""); setTargetBrandId("");
    setRelationship(candidate.relationship); setIdentityType("website");
  };
  const submit = async () => {
    if (!review || !note.trim()) return;
    await onDecide(review.candidate, {
      action: review.action, note: note.trim(),
      ...(targetBrandId.trim() ? { target_brand_id: targetBrandId.trim() } : {}),
      ...(relationship ? { relationship } : {}), ...(identityType ? { identity_type: identityType } : {}),
    });
    setReview(null);
  };
  return <section className="space-y-4" aria-label="Identity candidate queue">
    <div className="grid gap-2 md:grid-cols-3">
      <input aria-label="Filter entity" value={query.entity} placeholder="Entity" className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, entity: event.target.value, page: 1 })} />
      <select aria-label="Filter assurance" value={query.status} className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, status: event.target.value, page: 1 })}><option value="all">All statuses</option>{["discovered", "verified", "conflicting", "promoted", "rejected", "confirmed_mismatch"].map((value) => <option key={value}>{value}</option>)}</select>
      <select aria-label="Filter relationship" value={query.relationship} className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, relationship: event.target.value, page: 1 })}><option value="all">All relationships</option>{["official_controlled", "parent_organization", "endorsed_third_party_service"].map((value) => <option key={value}>{value}</option>)}</select>
    </div>
    {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm">{error} <button type="button" className="underline" onClick={onRetry}>Retry</button></div>}
    {loading ? <p role="status">Loading identity candidates…</p> : <div className="space-y-3">{page?.items.map((candidate) => <article key={candidate.association_id} className="rounded-xl border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">{candidate.entity_name}</h2><p className="break-all text-sm text-muted-foreground">{candidate.canonical_url}</p></div><span className="rounded-full bg-muted px-2 py-1 text-xs">{candidate.assurance}</span></div>
      <dl className="mt-3 grid gap-2 text-sm md:grid-cols-3"><div><dt className="text-muted-foreground">Relationship</dt><dd>{candidate.relationship}</dd></div><div><dt className="text-muted-foreground">Confidence</dt><dd>{Math.round(candidate.confidence * 100)}%</dd></div><div><dt className="text-muted-foreground">Expires</dt><dd>{candidate.expires_at ? new Date(candidate.expires_at).toLocaleString() : "terminal"}</dd></div></dl>
      <ul className="mt-3 space-y-1 text-xs text-muted-foreground">{candidate.observations.map((item) => <li key={item.evidence_ref}>{item.family} · {item.source_host} · {item.evidence_ref}</li>)}</ul>
      {!candidate.terminal_decision_id && <div className="mt-4 flex flex-wrap gap-2">{(["approve", "reject", "confirm_mismatch"] as const).map((action) => <button key={action} type="button" disabled={busy} className="rounded-lg border px-3 py-1.5 text-sm font-medium" onClick={() => startReview(candidate, action)}>{action.replace("_", " ")}</button>)}</div>}
    </article>)}</div>}
    {page && <div className="flex items-center justify-between text-sm"><span>{page.total} candidates</span><div className="flex gap-2"><button type="button" disabled={query.page <= 1} onClick={() => onQueryChange({ ...query, page: query.page - 1 })}>Previous</button><button type="button" disabled={query.page * page.limit >= page.total} onClick={() => onQueryChange({ ...query, page: query.page + 1 })}>Next</button></div></div>}
    {review && <div role="dialog" aria-modal="true" aria-label="Review identity candidate" className="rounded-xl border bg-background p-4 shadow-lg"><h2 className="font-semibold">{review.action.replace("_", " ")} {review.candidate.entity_name}</h2><textarea aria-label="Reviewer note" required value={note} placeholder="Reviewer note (required)" className="mt-3 min-h-24 w-full rounded-lg border p-2 text-sm" onChange={(event) => setNote(event.target.value)} />
      {review.action === "approve" && <div className="mt-2 grid gap-2 md:grid-cols-3"><input aria-label="Target brand ID" value={targetBrandId} placeholder="Target brand ID (optional)" className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setTargetBrandId(event.target.value)} /><select aria-label="Correct relationship" value={relationship} className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setRelationship(event.target.value as IdentityRelationshipV4)}>{["official_controlled", "parent_organization", "endorsed_third_party_service"].map((value) => <option key={value}>{value}</option>)}</select><select aria-label="Identity type" value={identityType} className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setIdentityType(event.target.value as OfficialIdentityTypeV4)}>{["website", "primary_website", "domain", "careers_page", "social_profile", "sub_organization"].map((value) => <option key={value}>{value}</option>)}</select></div>}
      <div className="mt-3 flex justify-end gap-2"><button type="button" onClick={() => setReview(null)}>Cancel</button><button type="button" disabled={busy || !note.trim()} className="rounded-lg bg-primary px-3 py-2 text-primary-foreground" onClick={() => void submit()}>Confirm</button></div></div>}
  </section>;
}
