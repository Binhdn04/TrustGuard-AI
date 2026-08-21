import { AlertTriangle, BadgeCheck, CircleHelp, ShieldQuestion } from "lucide-react";
import type { ReactNode } from "react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import type {
  OfficialVerificationComponentV4,
  VerificationStatusV4,
} from "@/types/generated/api-v4";

import { CopySafeValue } from "./copy-safe-value";

const STATUS: Record<VerificationStatusV4, { label: string; className: string }> = {
  VERIFIED: { label: "Da xac minh", className: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" },
  PARTIALLY_VERIFIED: { label: "Xac minh mot phan", className: "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300" },
  UNVERIFIED: { label: "Chua xac minh", className: "border-border bg-muted text-muted-foreground" },
  CONFLICTING: { label: "Thong tin mau thuan", className: "border-rose-500/25 bg-rose-500/10 text-rose-700 dark:text-rose-300" },
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
          : <span className="rounded-full border border-border px-2 py-1 text-[10px] font-bold uppercase text-muted-foreground">Khong ap dung</span>}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">Reason: <code>{component.reason_code}</code></p>
      {children}
      {component.evidence_refs.length > 0 && (
        <p className="mt-2 break-all text-[10px] text-muted-foreground">Evidence: {component.evidence_refs.join(", ")}</p>
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
            <p className="micro-label">Official link verification</p>
            <h3 id="official-verification-heading" className="mt-1 text-sm font-semibold">{status.label}</h3>
          </div>
        </div>
        <StatusBadge status={report.overall_status} />
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">Ket luan: <code>{report.reason_code}</code>. Trang chi hien thi ket qua API, khong tu suy dien URL la an toan.</p>
      {verifiedResourceAssociations.length > 0 && (
        <p className="mt-3 rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 text-xs leading-5 text-emerald-800 dark:text-emerald-200">
          Da tu dong xac nhan chuoi endorsement cho dung tai nguyen nay; ket qua khong mo rong thanh tin cay cho toan bo domain.
        </p>
      )}

      {mode === "simple" ? (
        viewModel.actions.length > 0 && (
          <div className="mt-3 rounded-xl bg-muted/55 p-3">
            <p className="text-xs font-semibold">Buoc an toan tiep theo</p>
            <ul className="mt-2 space-y-1 text-xs leading-5 text-muted-foreground">
              {viewModel.actions.slice(0, 3).map((action) => <li key={action.code}>- {action.label}</li>)}
            </ul>
          </div>
        )
      ) : (
        <div className="mt-4 space-y-4">
          <dl className="grid gap-2 text-xs sm:grid-cols-2">
            <div><dt className="text-muted-foreground">Publisher</dt><dd className="font-medium">{report.intent.organization_name ?? "Khong xac dinh"}</dd></div>
            <div><dt className="text-muted-foreground">Claim/topic</dt><dd className="font-medium">{report.intent.claim_summary ?? report.intent.topic ?? "Khong xac dinh"}</dd></div>
            <div><dt className="text-muted-foreground">Requested action</dt><dd className="font-medium">{report.intent.requested_action ?? "Khong xac dinh"}</dd></div>
            <div><dt className="text-muted-foreground">Strength</dt><dd className="font-medium">{status.label}</dd></div>
          </dl>

          <div className="grid gap-3">
            <ComponentCard title="Publisher verification" component={report.publisher_verification}>
              {report.publisher_verification.identity && (
                <dl className="mt-2 grid gap-1 text-xs">
                  <div><dt className="inline text-muted-foreground">Entity: </dt><dd className="inline">{report.publisher_verification.identity.entity_name}</dd></div>
                  <div><dt className="inline text-muted-foreground">Identity: </dt><dd className="inline">{report.publisher_verification.identity.identity_type} / {report.publisher_verification.identity.relationship}</dd></div>
                  <CopySafeValue value={report.publisher_verification.identity.display_value} label="publisher identity" />
                </dl>
              )}
            </ComponentCard>
            <ComponentCard title="Claim verification" component={report.claim_verification}>
              {report.claim_verification.topic && <p className="mt-2 text-xs">Topic: {report.claim_verification.topic}</p>}
            </ComponentCard>
            <ComponentCard title="Resource verification" component={report.resource_verification}>
              {report.resource_verification.match && (
                <div className="mt-2 space-y-2 text-xs">
                  <p>Match: <code>{report.resource_verification.match.status}</code></p>
                  <p className="text-muted-foreground">Resource / canonical chain (text only)</p>
                  {report.resource_verification.match.user_resource?.canonical_url && <CopySafeValue value={report.resource_verification.match.user_resource.canonical_url} label="submitted URL" />}
                  {report.resource_verification.match.official_resource?.canonical_url && <CopySafeValue value={report.resource_verification.match.official_resource.canonical_url} label="official canonical URL" />}
                </div>
              )}
            </ComponentCard>
          </div>

          {report.source_refs.length > 0 && <div><h4 className="text-xs font-semibold">Official sources</h4><div className="mt-2 space-y-2">{report.source_refs.map((source) => <div key={source.source_ref}><p className="mb-1 text-[10px] text-muted-foreground">{source.source_ref}</p><CopySafeValue value={source.display_url} label="source URL" /></div>)}</div></div>}
          {report.link_refs.length > 0 && <div><h4 className="text-xs font-semibold">Outbound references</h4><div className="mt-2 space-y-2">{report.link_refs.map((link) => <div key={link.link_ref}><p className="mb-1 text-[10px] text-muted-foreground">{link.role} / {link.link_ref}</p><CopySafeValue value={link.display_url} label="outbound URL" /></div>)}</div></div>}
          {(report.identity_associations?.length ?? 0) > 0 && (
            <div>
              <h4 className="text-xs font-semibold">Resource-scoped identity associations</h4>
              <p className="mt-1 text-xs text-muted-foreground">Ket qua nay chi ap dung cho dung tai nguyen duoc neu, khong xac nhan toan bo domain.</p>
              <div className="mt-2 space-y-2">
                {report.identity_associations?.map((association) => (
                  <article key={association.association_id} className="rounded-xl border border-border bg-background/55 p-3 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-medium">{association.entity_name}</p>
                      <span className="rounded-full border border-border px-2 py-1 text-[10px] font-bold uppercase">{association.assurance}</span>
                    </div>
                    <p className="mt-2 text-muted-foreground">{association.relationship} / confidence {association.confidence.toFixed(2)}</p>
                    <div className="mt-2"><CopySafeValue value={association.canonical_url} label="associated resource URL" /></div>
                  </article>
                ))}
              </div>
            </div>
          )}
          <div>
            <h4 className="text-xs font-semibold">Limitations</h4>
            {report.limitations.length > 0
              ? <ul className="mt-2 space-y-1 text-xs text-muted-foreground">{report.limitations.map((item) => <li key={item}>- {item}</li>)}</ul>
              : <p className="mt-2 text-xs text-muted-foreground">API khong bao cao limitation.</p>}
          </div>
        </div>
      )}
    </section>
  );
}
