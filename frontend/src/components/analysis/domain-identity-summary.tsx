import { Building2, FileQuestion, Globe2 } from "lucide-react";

import type { SecurityCaseViewModel, SecurityPresentationMode } from "@/lib/mappers/security-case-view-model";
import { securityLabel } from "@/lib/presentation/security-labels";

function verificationLabel(status: string | null | undefined, applicable = true): string {
  if (!applicable) return "Không áp dụng";
  return {
    VERIFIED: "Đã xác minh",
    PARTIALLY_VERIFIED: "Xác minh một phần",
    UNVERIFIED: "Chưa xác minh quan hệ",
    CONFLICTING: "Thông tin mâu thuẫn",
  }[status ?? ""] ?? "Chưa có dữ liệu xác minh";
}

function combinedVerificationStatus(statuses: Array<string | null | undefined>): string | null {
  const present = statuses.filter((status): status is string => status !== null && status !== undefined);
  if (present.includes("CONFLICTING")) return "CONFLICTING";
  if (present.includes("VERIFIED") && (present.includes("UNVERIFIED") || present.includes("PARTIALLY_VERIFIED"))) {
    return "PARTIALLY_VERIFIED";
  }
  if (present.includes("UNVERIFIED")) return "UNVERIFIED";
  if (present.includes("PARTIALLY_VERIFIED")) return "PARTIALLY_VERIFIED";
  if (present.includes("VERIFIED")) return "VERIFIED";
  return null;
}

export function DomainIdentitySummary({ viewModel, mode }: {
  viewModel: SecurityCaseViewModel;
  mode: SecurityPresentationMode;
}) {
  const familiarity = viewModel.evidence
    .map((item) => item.evidence)
    .filter((item) => item.type === "domain_familiarity" && item.domain_familiarity)
    .map((item) => ({ evidence: item, details: item.domain_familiarity! }));
  const platform = familiarity.find((item) => item.details.classification === "reviewed_platform_service");
  const firstParty = familiarity.find((item) => item.details.classification === "reviewed_first_party");
  const ranked = familiarity.find((item) => item.details.classification === "ranked_domain");
  const domainSummary = platform
    ? `Nền tảng đã duyệt: ${platform.details.platform_name} (${platform.details.observed_host})`
    : firstParty
      ? `Tên miền chính chủ đã duyệt: ${firstParty.details.observed_host}`
      : ranked
        ? `Tên miền có dữ liệu xếp hạng${ranked.details.popularity_rank ? ` #${ranked.details.popularity_rank}` : ranked.details.popularity_bucket ? `, nhóm ${ranked.details.popularity_bucket}` : ""}`
        : "Chưa có dữ liệu mức độ quen thuộc cho tên miền";
  const report = viewModel.officialVerification;
  const ownership = report?.domain_ownership_verification;
  const resource = report?.resource_verification;
  const claim = report?.claim_verification;
  const action = report?.action_endorsement_verification;
  const exactResourceAssociation = (report?.identity_associations ?? []).some(
    (item) => item.assurance === "verified" && item.relationship === "endorsed_third_party_service",
  );
  const organizationRelationshipStatus = combinedVerificationStatus([
    ownership?.applicable ? ownership.status : null,
    resource?.applicable ? resource.status : null,
    exactResourceAssociation ? "VERIFIED" : null,
  ]);
  const contentActionStatus = combinedVerificationStatus([
    claim?.applicable ? claim.status : null,
    resource?.applicable ? resource.status : null,
    action?.applicable ? action.status : null,
  ]);
  const axes = [
    {
      title: "Tên miền/nền tảng",
      value: domainSummary,
      detail: "Nền tảng quen thuộc không bảo chứng nội dung.",
      reason: familiarity[0]?.evidence.source,
      Icon: Globe2,
    },
    {
      title: "Quan hệ với tổ chức",
      value: organizationRelationshipStatus
        ? verificationLabel(organizationRelationshipStatus)
        : "Chưa xác minh quan hệ với tổ chức",
      detail: exactResourceAssociation
        ? "Nguồn chính thức đã endorse đúng tài nguyên được gửi; không suy ra quyền sở hữu toàn domain."
        : "Tổng hợp ownership tên miền và đối chiếu tài nguyên cụ thể; không suy diễn từ độ quen thuộc nền tảng.",
      reason: ownership?.reason_code ?? resource?.reason_code,
      Icon: Building2,
    },
    {
      title: "Nội dung / hành động",
      value: contentActionStatus
        ? verificationLabel(contentActionStatus)
        : "Chưa có nội dung hoặc hành động cần xác minh",
      detail: action?.applicable
        ? "Tổng hợp claim, tài nguyên và endorsement của hành động được yêu cầu."
        : resource?.match?.status
          ? `Đối chiếu tài nguyên: ${securityLabel(resource.match.status)}`
          : "Mức độ quen thuộc không xác minh claim, biểu mẫu, bài đăng, tệp hoặc hành động.",
      reason: action?.reason_code ?? claim?.reason_code ?? resource?.reason_code,
      Icon: FileQuestion,
    },
  ];

  return (
    <section aria-labelledby="domain-identity-summary-heading" className="rounded-2xl border border-border bg-card p-4">
      <p className="micro-label">Ngữ cảnh bảo mật</p>
      <h3 id="domain-identity-summary-heading" className="mt-1 text-sm font-semibold">Ba lớp cần phân biệt</h3>
      <div className="mt-3 grid gap-3 lg:grid-cols-3">
        {axes.map(({ title, value, detail, reason, Icon }) => (
          <article key={title} className="rounded-xl border border-border bg-background/55 p-3">
            <div className="flex items-center gap-2"><Icon className="size-4 text-primary" aria-hidden="true" /><h4 className="text-xs font-semibold">{title}</h4></div>
            <p className="mt-2 text-sm font-medium leading-5">{value}</p>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p>
            {mode === "analyst" && reason && <p className="mt-2 break-all font-mono text-[10px] text-muted-foreground">{reason}</p>}
          </article>
        ))}
      </div>
    </section>
  );
}
