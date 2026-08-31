import type { SecurityMemoryRecordV4 } from "@/types/generated/api-v4";

import { riskLabel, securityLabel } from "./security-labels";

export interface SecurityMemoryPresentation {
  title: string;
  subtitle: string | null;
  summary: string[];
  threatLabel: string;
  scenarioLabel: string;
  actionLabel: string;
  patternLabels: string[];
  reportLabel: string;
  evidenceLabel: string;
}

function lowerFirst(value: string): string {
  if (!value) return value;
  return value.charAt(0).toLocaleLowerCase("vi-VN") + value.slice(1);
}

function countLabel(count: number, noun: string): string {
  return `${count} ${noun}`;
}

export function presentSecurityMemory(record: SecurityMemoryRecordV4): SecurityMemoryPresentation {
  const primaryDomain = record.canonical_domains[0] ?? null;
  const title = record.claimed_brand ?? primaryDomain ?? "Bản ghi bảo mật";
  const subtitle = record.claimed_brand && primaryDomain ? `Domain chính: ${primaryDomain}` : null;
  const threatUnknown = record.threat_type === "UNDETERMINED_SECURITY_THREAT";
  const scenarioUnknown = record.scenario === "unknown";
  const threatLabel = securityLabel(record.threat_type);
  const scenarioLabel = securityLabel(record.scenario);
  const actionLabel = record.requested_action ? securityLabel(record.requested_action) : "Chưa ghi nhận";
  const patternLabels = record.security_patterns.map((pattern) => securityLabel(pattern));
  const summary = [
    `Kết quả check ghi nhận: ${riskLabel(record.risk)}.`,
    threatUnknown
      ? "Chưa xác định được loại mối đe dọa."
      : `Loại mối đe dọa được ghi nhận: ${lowerFirst(threatLabel)}.`,
  ];

  if (!scenarioUnknown) summary.push(`Bối cảnh liên quan: ${lowerFirst(scenarioLabel)}.`);
  if (record.requested_action) summary.push(`Hành động được ghi nhận: ${lowerFirst(actionLabel)}.`);
  if (patternLabels.length === 0) summary.push("Chưa ghi nhận dấu hiệu bổ trợ.");

  return {
    title,
    subtitle,
    summary,
    threatLabel,
    scenarioLabel,
    actionLabel,
    patternLabels,
    reportLabel: record.report_count === 0
      ? "Chưa có báo cáo liên kết"
      : countLabel(record.report_count, "báo cáo liên kết"),
    evidenceLabel: record.evidence_refs.length === 0
      ? "Chưa có bằng chứng tham chiếu"
      : countLabel(record.evidence_refs.length, "bằng chứng"),
  };
}
