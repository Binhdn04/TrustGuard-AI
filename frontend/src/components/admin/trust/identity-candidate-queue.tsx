"use client";

import { Plus } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type {
  IdentityCandidateDecisionActionV4,
  IdentityCandidateDecisionRequestV4,
  IdentityCandidatePageV4,
  IdentityCandidateV4,
  IdentityRelationshipV4,
  ManualIdentityCandidateCreateRequestV4,
  OfficialIdentityTypeV4,
} from "@/types/generated/api-v4";
import { securityLabel, statusLabel } from "@/lib/presentation/security-labels";

export type IdentityCandidateQuery = {
  entity: string; status: string; relationship: string; page: number;
};

type Props = {
  page: IdentityCandidatePageV4 | null; query: IdentityCandidateQuery; loading: boolean;
  busy: boolean; error: string | null; onQueryChange: (query: IdentityCandidateQuery) => void;
  onCreateManual: (request: ManualIdentityCandidateCreateRequestV4) => Promise<void>;
  onDecide: (candidate: IdentityCandidateV4, request: IdentityCandidateDecisionRequestV4) => Promise<void>;
  onRetry: () => void;
};

const manualIdentityTypes: OfficialIdentityTypeV4[] = ["primary_website", "website", "domain", "careers_page", "social_profile"];
const relationships: IdentityRelationshipV4[] = ["official_controlled", "parent_organization", "endorsed_third_party_service"];

export function IdentityCandidateQueue({ page, query, loading, busy, error, onQueryChange, onCreateManual, onDecide, onRetry }: Props) {
  const [manualOpen, setManualOpen] = useState(false);
  const [manualEntity, setManualEntity] = useState("");
  const [manualValue, setManualValue] = useState("");
  const [manualSource, setManualSource] = useState("");
  const [manualType, setManualType] = useState<OfficialIdentityTypeV4>("website");
  const [manualRelationship, setManualRelationship] = useState<IdentityRelationshipV4>("official_controlled");
  const [review, setReview] = useState<{ candidate: IdentityCandidateV4; action: IdentityCandidateDecisionActionV4 } | null>(null);
  const [note, setNote] = useState("");
  const [targetBrandId, setTargetBrandId] = useState("");
  const [relationship, setRelationship] = useState<IdentityRelationshipV4 | "">("");
  const [identityType, setIdentityType] = useState<OfficialIdentityTypeV4 | "">("");
  const reviewFormRef = useRef<HTMLDivElement>(null);
  const reviewNoteRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!review) return;
    reviewFormRef.current?.scrollIntoView?.({ behavior: "smooth", block: "center" });
    reviewNoteRef.current?.focus();
  }, [review]);

  const resetManual = () => {
    setManualOpen(false); setManualEntity(""); setManualValue(""); setManualSource("");
    setManualType("website"); setManualRelationship("official_controlled");
  };
  const submitManual = async () => {
    if (!manualEntity.trim() || !manualValue.trim() || !manualSource.trim()) return;
    await onCreateManual({
      entity_name: manualEntity.trim(), identity_value: manualValue.trim(), identity_type: manualType,
      relationship: manualRelationship, source_url: manualSource.trim(),
    });
    resetManual();
  };
  const startReview = (candidate: IdentityCandidateV4, action: IdentityCandidateDecisionActionV4) => {
    setReview({ candidate, action }); setNote(""); setTargetBrandId("");
    setRelationship(candidate.relationship); setIdentityType("website");
  };
  const submitReview = async () => {
    if (!review || !note.trim()) return;
    await onDecide(review.candidate, {
      action: review.action, note: note.trim(),
      ...(targetBrandId.trim() ? { target_brand_id: targetBrandId.trim() } : {}),
      ...(relationship ? { relationship } : {}), ...(identityType ? { identity_type: identityType } : {}),
    });
    setReview(null);
  };

  return <section className="space-y-4" aria-label="Hàng đợi ứng viên danh tính">
    <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div><h2 className="text-xl font-bold">Duyệt định danh</h2><p className="mt-1 text-sm text-muted-foreground">Mọi định danh, kể cả do admin tự thêm, đều chỉ là ứng viên cho đến khi được duyệt.</p></div><button type="button" onClick={() => setManualOpen(true)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground"><Plus className="size-4" />Thêm định danh thủ công</button></header>

    {manualOpen && <section aria-label="Thêm định danh thủ công" className="space-y-3 rounded-2xl border border-border bg-card p-4"><div><h3 className="font-semibold">Đề xuất định danh để duyệt</h3><p className="mt-1 text-xs text-muted-foreground">Thao tác này không tự thêm vào thương hiệu và không làm thay đổi kết quả kiểm tra. Sau khi gửi, hãy duyệt ứng viên bên dưới.</p></div><div className="grid gap-3 md:grid-cols-2">
      <label className="text-xs font-semibold">Tên thương hiệu hoặc tổ chức<input aria-label="Tên thương hiệu của định danh thủ công" value={manualEntity} onChange={(event) => setManualEntity(event.target.value)} placeholder="Ví dụ: Example Bank" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label>
      <label className="text-xs font-semibold">Loại định danh<select aria-label="Loại định danh thủ công" value={manualType} onChange={(event) => setManualType(event.target.value as OfficialIdentityTypeV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">{manualIdentityTypes.map((item) => <option key={item} value={item}>{securityLabel(item)}</option>)}</select></label>
      <label className="text-xs font-semibold">URL hoặc domain định danh<input aria-label="Giá trị định danh thủ công" value={manualValue} onChange={(event) => setManualValue(event.target.value)} placeholder={manualType === "domain" || manualType === "primary_website" ? "bank.example" : "https://…"} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /></label>
      <label className="text-xs font-semibold">Quan hệ với thương hiệu<select aria-label="Quan hệ định danh thủ công" value={manualRelationship} onChange={(event) => setManualRelationship(event.target.value as IdentityRelationshipV4)} className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm">{relationships.map((item) => <option key={item} value={item}>{securityLabel(item)}</option>)}</select></label>
      <label className="text-xs font-semibold md:col-span-2">URL nguồn xác minh<input aria-label="URL nguồn xác minh định danh thủ công" value={manualSource} onChange={(event) => setManualSource(event.target.value)} placeholder="https://…" className="mt-1 w-full rounded-xl border border-border bg-background px-3 py-2 text-sm" /><p className="mt-1 font-normal text-muted-foreground">Query và fragment không được lưu. Server không tự truy cập URL này.</p></label>
    </div><div className="flex justify-end gap-2"><button type="button" onClick={resetManual} className="rounded-xl px-4 py-2 text-sm">Hủy</button><button type="button" disabled={busy || !manualEntity.trim() || !manualValue.trim() || !manualSource.trim()} onClick={() => void submitManual()} className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-45">Gửi vào hàng đợi duyệt</button></div></section>}

    <div className="grid gap-2 md:grid-cols-3">
      <input aria-label="Lọc theo đơn vị" value={query.entity} placeholder="Tên đơn vị" className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, entity: event.target.value, page: 1 })} />
      <select aria-label="Lọc theo trạng thái xác minh" value={query.status} className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, status: event.target.value, page: 1 })}><option value="all">Tất cả trạng thái</option>{["discovered", "verified", "conflicting", "promoted", "rejected", "confirmed_mismatch"].map((value) => <option key={value} value={value}>{statusLabel(value)}</option>)}</select>
      <select aria-label="Lọc theo quan hệ" value={query.relationship} className="rounded-lg border bg-background px-3 py-2 text-sm" onChange={(event) => onQueryChange({ ...query, relationship: event.target.value, page: 1 })}><option value="all">Tất cả quan hệ</option>{relationships.map((value) => <option key={value} value={value}>{securityLabel(value)}</option>)}</select>
    </div>
    {error && <div role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm">{error} <button type="button" className="underline" onClick={onRetry}>Thử lại</button></div>}
    {loading ? <p role="status">Đang tải ứng viên danh tính…</p> : <div className="space-y-3">{page?.items.map((candidate) => <article key={candidate.association_id} className="rounded-xl border p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">{candidate.entity_name}</h2><p className="break-all text-sm text-muted-foreground">{candidate.canonical_url}</p></div><span className="rounded-full bg-muted px-2 py-1 text-xs">{statusLabel(candidate.assurance)}</span></div><dl className="mt-3 grid gap-2 text-sm md:grid-cols-3"><div><dt className="text-muted-foreground">Quan hệ</dt><dd>{securityLabel(candidate.relationship)}</dd></div><div><dt className="text-muted-foreground">Mức chắc chắn</dt><dd>{Math.round(candidate.confidence * 100)}%</dd></div><div><dt className="text-muted-foreground">Hết hạn</dt><dd>{candidate.expires_at ? new Date(candidate.expires_at).toLocaleString("vi-VN") : "Đã kết thúc"}</dd></div></dl><ul className="mt-3 space-y-1 text-xs text-muted-foreground">{candidate.observations.map((item) => <li key={item.evidence_ref} className="break-all">{item.family} · {item.canonical_url} · {item.evidence_ref}</li>)}</ul>{!candidate.terminal_decision_id && <div className="mt-4 flex flex-wrap gap-2">{(["approve", "reject", "confirm_mismatch"] as const).map((action) => <button key={action} type="button" disabled={busy} className="rounded-lg border px-3 py-1.5 text-sm font-medium" onClick={() => startReview(candidate, action)}>{securityLabel(action)}</button>)}</div>}</article>)}</div>}
    {page && <div className="flex items-center justify-between text-sm"><span>{page.total} ứng viên</span><div className="flex gap-2"><button type="button" disabled={query.page <= 1} onClick={() => onQueryChange({ ...query, page: query.page - 1 })}>Trước</button><button type="button" disabled={query.page * page.limit >= page.total} onClick={() => onQueryChange({ ...query, page: query.page + 1 })}>Sau</button></div></div>}
    {review && (
      <div ref={reviewFormRef} role="dialog" aria-modal="true" aria-label="Duyệt ứng viên danh tính" className="rounded-xl border bg-background p-4 shadow-lg">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Đang duyệt</p>
        <h2 className="mt-1 font-semibold">{securityLabel(review.action)} {review.candidate.entity_name}</h2>
        <div className="mt-3 rounded-lg bg-muted/60 p-3 text-sm">
          <p className="break-all font-medium">{review.candidate.canonical_url}</p>
          <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <div><dt className="inline">Quan hệ: </dt><dd className="inline">{securityLabel(review.candidate.relationship)}</dd></div>
            <div><dt className="inline">Mức chắc chắn: </dt><dd className="inline">{Math.round(review.candidate.confidence * 100)}%</dd></div>
            <div><dt className="inline">Trạng thái: </dt><dd className="inline">{statusLabel(review.candidate.assurance)}</dd></div>
          </dl>
        </div>
        <textarea ref={reviewNoteRef} aria-label="Ghi chú của người duyệt" required value={note} placeholder="Ghi chú của người duyệt (bắt buộc)" className="mt-3 min-h-24 w-full rounded-lg border p-2 text-sm" onChange={(event) => setNote(event.target.value)} />
        {review.action === "approve" && <div className="mt-2 grid gap-2 md:grid-cols-3"><input aria-label="Mã thương hiệu đích" value={targetBrandId} placeholder="Mã thương hiệu đích (không bắt buộc)" className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setTargetBrandId(event.target.value)} /><select aria-label="Quan hệ chính xác" value={relationship} className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setRelationship(event.target.value as IdentityRelationshipV4)}>{relationships.map((value) => <option key={value} value={value}>{securityLabel(value)}</option>)}</select><select aria-label="Loại danh tính" value={identityType} className="rounded-lg border px-2 py-2 text-sm" onChange={(event) => setIdentityType(event.target.value as OfficialIdentityTypeV4)}>{manualIdentityTypes.map((value) => <option key={value} value={value}>{securityLabel(value)}</option>)}</select></div>}
        <div className="mt-3 flex justify-end gap-2"><button type="button" onClick={() => setReview(null)}>Hủy</button><button type="button" disabled={busy || !note.trim()} className="rounded-lg bg-primary px-3 py-2 text-primary-foreground" onClick={() => void submitReview()}>Xác nhận</button></div>
      </div>
    )}
  </section>;
}
