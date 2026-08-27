import { AlertTriangle, BadgeCheck, CircleHelp, ShieldQuestion } from "lucide-react";
import type { ReactNode } from "react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { securityLabel } from "@/lib/presentation/security-labels";
import type {
  OfficialVerificationComponentV4,
  VerificationStatusV4,
} from "@/types/generated/api-v4";

import { CopySafeValue } from "./copy-safe-value";

const STATUS: Record<VerificationStatusV4, { label: string; className: string }> = {
  VERIFIED: { label: "Đã xác minh", className: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" },
  PARTIALLY_VERIFIED: { label: "Xác minh một phần", className: "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300" },
  UNVERIFIED: { label: "Chưa xác minh quan hệ chính thức", className: "border-border bg-muted text-muted-foreground" },
  CONFLICTING: { label: "Thông tin mâu thuẫn", className: "border-rose-500/25 bg-rose-500/10 text-rose-700 dark:text-rose-300" },
};

function StatusBadge({ status }: { status: VerificationStatusV4 }) {
  const presentation = STATUS[status];
  return <span className={`rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-wide ${presentation.className}`}>{presentation.label}</span>;
}

function ComponentCard({ title, component, children }: {
  title: string;
  component: OfficialVerificationComponentV4;
  children?: ReactNode;
}) {
  return (
    <article className="rounded-xl border border-border bg-background/55 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-xs font-semibold">{title}</h4>
        {component.applicable && component.status
          ? <StatusBadge status={component.status} />
          : <span className="rounded-full border border-border px-2 py-1 text-[10px] font-bold uppercase text-muted-foreground">Không áp dụng</span>}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">Lý do: <code>{component.reason_code}</code></p>
      {children}
      {component.evidence_refs.length > 0 && (
        <p className="mt-2 break-all text-[10px] text-muted-foreground">Bằng chứng: {component.evidence_refs.join(", ")}</p>
      )}
    </article>
  );
}

export function OfficialVerificationPanel({ viewModel, mode }: {
  viewModel: SecurityCaseViewModel;
  mode: SecurityPresentationMode;
}) {
  const report = viewModel.officialVerification;
  if (!report) return null;
  const verifiedResourceAssociations = (report.identity_associations ?? []).filter(
    (item) => item.assurance === "verified" && item.relationship === "endorsed_third_party_service",
  );
  const status = STATUS[report.overall_status];
  const verificationLayers = [
    ["Quyền sở hữu domain", report.domain_ownership_verification],
    ["Tài nguyên / quan hệ tổ chức", report.resource_verification],
    ["Xác nhận hành động", report.action_endorsement_verification],
  ] as const;
  const conflictComponents: Array<[string, OfficialVerificationComponentV4 | undefined]> = [
    ["Publisher", report.publisher_verification],
    ["Nội dung xác nhận", report.claim_verification],
    ["Tài nguyên", report.resource_verification],
    ["Hành động", report.action_endorsement_verification],
  ];
  const conflictingComponent = conflictComponents.find(
    ([, component]) => component?.applicable && component.status === "CONFLICTING",
  );
  const Icon = report.overall_status === "VERIFIED"
    ? BadgeCheck
    : report.overall_status === "CONFLICTING"
      ? AlertTriangle
      : report.overall_status === "PARTIALLY_VERIFIED"
        ? ShieldQuestion
        : CircleHelp;

  return (
    <section aria-labelledby="official-verification-heading" className="rounded-2xl border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Icon className="mt-0.5 size-5 shrink-0 text-primary" aria-hidden="true" />
          <div>
            <p className="micro-label">Xác minh nguồn chính thức</p>
            <h3 id="official-verification-heading" className="mt-1 text-sm font-semibold">Xác minh quan hệ chính thức</h3>
          </div>
        </div>
        <StatusBadge status={report.overall_status} />
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">
        Kết quả này mô tả quan hệ giữa đơn vị phát hành/tài nguyên với nguồn chính thức; không tự suy diễn URL là an toàn.
        {mode === "analyst" && <> Lý do: <code>{report.reason_code}</code>.</>}
      </p>
      {conflictingComponent && (
        <p className="mt-3 rounded-xl border border-amber-500/25 bg-amber-500/10 p-3 text-xs leading-5 text-amber-800 dark:text-amber-200">
          Mâu thuẫn nằm ở bước xác minh {conflictingComponent[0].toLowerCase()}, không phải kết luận tên miền này độc hại.
        </p>
      )}
      {verificationLayers.some(([, component]) => component?.applicable) && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {verificationLayers.map(([label, component]) => (
            <div key={label} className="rounded-xl border border-border bg-background/55 p-3">
              <p className="text-xs font-semibold">{label}</p>
              <div className="mt-2">
                {component?.applicable && component.status
                  ? <StatusBadge status={component.status} />
                  : <span className="text-[10px] uppercase text-muted-foreground">Không áp dụng</span>}
              </div>
            </div>
          ))}
        </div>
      )}
      {report.domain_ownership_verification?.status === "VERIFIED"
        && report.action_endorsement_verification?.status === "UNVERIFIED" && (
        <p className="mt-3 rounded-xl border border-amber-500/25 bg-amber-500/10 p-3 text-xs leading-5 text-amber-800 dark:text-amber-200">
          Tên miền chính thức đã được xác minh, nhưng yêu cầu hành động chưa được xác minh. Không nhập mật khẩu hay OTP chỉ dựa trên tin nhắn.
        </p>
      )}
      {verifiedResourceAssociations.length > 0 && (
        <p className="mt-3 rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 text-xs leading-5 text-emerald-800 dark:text-emerald-200">
          Đã tự động xác nhận chuỗi chứng thực cho đúng tài nguyên này; kết quả không mở rộng thành tin cậy cho toàn bộ domain.
        </p>
      )}

      {mode === "simple" ? (
        viewModel.actions.length > 0 && (
          <div className="mt-3 rounded-xl bg-muted/55 p-3">
            <p className="text-xs font-semibold">Bước an toàn tiếp theo</p>
            <ul className="mt-2 space-y-1 text-xs leading-5 text-muted-foreground">
              {viewModel.actions.slice(0, 3).map((action) => <li key={action.code}>- {action.label}</li>)}
            </ul>
          </div>
        )
      ) : (
        <div className="mt-4 space-y-4">
          <dl className="grid gap-2 text-xs sm:grid-cols-2">
            <div><dt className="text-muted-foreground">Đơn vị phát hành</dt><dd className="font-medium">{report.intent.organization_name ?? "Không xác định"}</dd></div>
            <div><dt className="text-muted-foreground">Nội dung/chủ đề</dt><dd className="font-medium">{report.intent.claim_summary ?? report.intent.topic ?? "Không xác định"}</dd></div>
            <div><dt className="text-muted-foreground">Hành động được yêu cầu</dt><dd className="font-medium">{securityLabel(report.intent.requested_action)}</dd></div>
            <div><dt className="text-muted-foreground">Mức xác minh</dt><dd className="font-medium">{status.label}</dd></div>
          </dl>

          <div className="grid gap-3">
            <ComponentCard title="Xác minh đơn vị phát hành" component={report.publisher_verification}>
              {report.publisher_verification.identity && (
                <dl className="mt-2 grid gap-1 text-xs">
                  <div><dt className="inline text-muted-foreground">Đơn vị: </dt><dd className="inline">{report.publisher_verification.identity.entity_name}</dd></div>
                  <div><dt className="inline text-muted-foreground">Danh tính: </dt><dd className="inline">{securityLabel(report.publisher_verification.identity.identity_type)} / {securityLabel(report.publisher_verification.identity.relationship)}</dd></div>
                  <CopySafeValue value={report.publisher_verification.identity.display_value} label="danh tính đơn vị phát hành" />
                </dl>
              )}
            </ComponentCard>
            <ComponentCard title="Xác minh nội dung" component={report.claim_verification}>
              {report.claim_verification.topic && <p className="mt-2 text-xs">Chủ đề: {report.claim_verification.topic}</p>}
            </ComponentCard>
            <ComponentCard title="Xác minh tài nguyên" component={report.resource_verification}>
              {report.resource_verification.match && (
                <div className="mt-2 space-y-2 text-xs">
                  <p>Đối chiếu: <code>{securityLabel(report.resource_verification.match.status)}</code></p>
                  <p className="text-muted-foreground">Chuỗi tài nguyên / URL chuẩn hóa (chỉ văn bản)</p>
                  {report.resource_verification.match.user_resource?.canonical_url && <CopySafeValue value={report.resource_verification.match.user_resource.canonical_url} label="URL đã gửi" />}
                  {report.resource_verification.match.official_resource?.canonical_url && <CopySafeValue value={report.resource_verification.match.official_resource.canonical_url} label="URL chuẩn hóa chính thức" />}
                </div>
              )}
            </ComponentCard>
          </div>

          {report.source_refs.length > 0 && <div><h4 className="text-xs font-semibold">Nguồn chính thức</h4><div className="mt-2 space-y-2">{report.source_refs.map((source) => <div key={source.source_ref}><p className="mb-1 text-[10px] text-muted-foreground">{source.source_ref}</p><CopySafeValue value={source.display_url} label="URL nguồn" /></div>)}</div></div>}
          {report.link_refs.length > 0 && <div><h4 className="text-xs font-semibold">Tham chiếu ra ngoài</h4><div className="mt-2 space-y-2">{report.link_refs.map((link) => <div key={link.link_ref}><p className="mb-1 text-[10px] text-muted-foreground">{link.role} / {link.link_ref}</p><CopySafeValue value={link.display_url} label="URL tham chiếu" /></div>)}</div></div>}
          {(report.identity_associations?.length ?? 0) > 0 && (
            <div>
              <h4 className="text-xs font-semibold">Liên kết danh tính theo tài nguyên</h4>
              <p className="mt-1 text-xs text-muted-foreground">Kết quả này chỉ áp dụng cho đúng tài nguyên được nêu, không xác nhận toàn bộ domain.</p>
              <div className="mt-2 space-y-2">
                {report.identity_associations?.map((association) => (
                  <article key={association.association_id} className="rounded-xl border border-border bg-background/55 p-3 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-medium">{association.entity_name}</p>
                      <span className="rounded-full border border-border px-2 py-1 text-[10px] font-bold uppercase">{securityLabel(association.assurance)}</span>
                    </div>
                    <p className="mt-2 text-muted-foreground">{securityLabel(association.relationship)} / mức chắc chắn {Math.round(association.confidence * 100)}%</p>
                    <div className="mt-2"><CopySafeValue value={association.canonical_url} label="URL tài nguyên liên kết" /></div>
                  </article>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
