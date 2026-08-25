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
  const publisher = report?.publisher_verification;
  const resource = report?.resource_verification;
  const axes = [
    {
      title: "Tên miền/nền tảng",
      value: domainSummary,
      detail: "Nền tảng quen thuộc không bảo chứng nội dung.",
      reason: familiarity[0]?.evidence.source,
      Icon: Globe2,
    },
    {
      title: "Danh tính đơn vị phát hành",
      value: publisher ? verificationLabel(publisher.status, publisher.applicable) : "Chưa có dữ liệu xác minh đơn vị phát hành",
      detail: publisher?.identity?.entity_name ?? "Không suy diễn đơn vị phát hành từ chủ sở hữu nền tảng.",
      reason: publisher?.reason_code,
      Icon: Building2,
    },
    {
      title: "Tài nguyên/hành động cụ thể",
      value: resource
        ? verificationLabel(resource.status, resource.applicable)
        : viewModel.context?.urls.length
          ? "Chưa xác minh tài nguyên cụ thể"
          : "Không áp dụng",
      detail: resource?.match?.status ? `Đối chiếu tài nguyên: ${securityLabel(resource.match.status)}` : "Mức độ quen thuộc không xác minh biểu mẫu, video, bài đăng hoặc tệp cụ thể.",
      reason: resource?.reason_code,
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

