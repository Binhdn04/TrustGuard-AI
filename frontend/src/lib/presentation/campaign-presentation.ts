import type { SecurityCampaignRecordV4 } from "@/types/generated/api-v4";

import { securityLabel } from "./security-labels";

export type CampaignSignalGroup = "primary" | "destination" | "supporting" | "technical" | "other";

export interface CampaignSignalPresentation {
  raw: string;
  prefix: string;
  value: string;
  label: string;
  count: number;
  group: CampaignSignalGroup;
}

export interface CampaignPresentation {
  title: string;
  subtitle: string | null;
  summary: string[];
  topSignals: CampaignSignalPresentation[];
  groups: Record<CampaignSignalGroup, CampaignSignalPresentation[]>;
}

const GROUP_BY_PREFIX: Record<string, CampaignSignalGroup> = {
  threat: "primary",
  scenario: "primary",
  action: "primary",
  brand: "primary",
  domain: "destination",
  redirect: "destination",
  pattern: "supporting",
  lexical: "technical",
};

const PREFIX_PRIORITY: Record<string, number> = {
  threat: 0,
  scenario: 1,
  action: 2,
  brand: 3,
  domain: 4,
  redirect: 5,
  pattern: 6,
  lexical: 7,
};

const LEXICAL_LABELS: Record<string, string> = {
  "host:punycode": "Hostname sử dụng Punycode",
  "host:hyphenated": "Hostname chứa dấu gạch nối",
  "host:contains_digit": "Hostname chứa chữ số",
};

function lowerFirst(value: string): string {
  if (!value) return value;
  return value.charAt(0).toLocaleLowerCase("vi-VN") + value.slice(1);
}

function humanizeLexical(value: string): string {
  const exact = LEXICAL_LABELS[value];
  if (exact) return exact;
  if (value.startsWith("path_depth:")) {
    return `Độ sâu đường dẫn: ${value.slice("path_depth:".length)}`;
  }
  if (value.startsWith("path:")) {
    return `Đường dẫn chứa “${value.slice("path:".length)}”`;
  }
  return value.replaceAll("_", " ");
}

function signalLabel(prefix: string, value: string): string {
  if (prefix === "domain" || prefix === "redirect" || prefix === "brand") return value;
  if (prefix === "lexical") return humanizeLexical(value);
  return securityLabel(value);
}

export function parseCampaignSignal(raw: string, count: number): CampaignSignalPresentation {
  const separator = raw.indexOf(":");
  const prefix = separator >= 0 ? raw.slice(0, separator) : "unknown";
  const value = separator >= 0 ? raw.slice(separator + 1) : raw;
  return {
    raw,
    prefix,
    value,
    label: signalLabel(prefix, value),
    count,
    group: GROUP_BY_PREFIX[prefix] ?? "other",
  };
}

function compareSignals(left: CampaignSignalPresentation, right: CampaignSignalPresentation): number {
  return right.count - left.count
    || (PREFIX_PRIORITY[left.prefix] ?? 99) - (PREFIX_PRIORITY[right.prefix] ?? 99)
    || left.label.localeCompare(right.label, "vi");
}

function firstUseful(
  signals: CampaignSignalPresentation[],
  prefix: string,
): CampaignSignalPresentation | undefined {
  return signals.find((signal) => {
    if (signal.prefix !== prefix) return false;
    const normalized = signal.value.toLocaleLowerCase("en-US");
    return normalized !== "unknown" && normalized !== "undetermined_security_threat";
  });
}

function formatDuration(startValue: string, endValue: string): string {
  const durationMs = Math.max(0, new Date(endValue).getTime() - new Date(startValue).getTime());
  const minutes = Math.floor(durationMs / 60_000);
  if (minutes < 1) return "dưới 1 phút";
  if (minutes < 60) return `${minutes} phút`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  if (hours < 24) return remainingMinutes ? `${hours} giờ ${remainingMinutes} phút` : `${hours} giờ`;
  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  return remainingHours ? `${days} ngày ${remainingHours} giờ` : `${days} ngày`;
}

function summaryFact(signal: CampaignSignalPresentation): string {
  switch (signal.prefix) {
    case "threat":
      return `dấu hiệu ${lowerFirst(signal.label)}`;
    case "scenario":
      return `bối cảnh ${lowerFirst(signal.label)}`;
    case "action":
      return `hành vi ${lowerFirst(signal.label)}`;
    case "brand":
      return `đơn vị “${signal.label}”`;
    case "domain":
      return `domain ${signal.label}`;
    case "redirect":
      return `chuyển hướng đến ${signal.label}`;
    default:
      return lowerFirst(signal.label);
  }
}

function describeSignal(signal: CampaignSignalPresentation, memberCount: number): string {
  const subject = signal.count === memberCount
    ? `Cả ${memberCount} phân tích`
    : `${signal.count}/${memberCount} phân tích`;
  return `${subject} ghi nhận ${summaryFact(signal)}.`;
}

export function presentCampaign(record: SecurityCampaignRecordV4): CampaignPresentation {
  const signals = Object.entries(record.aggregate_signals)
    .map(([raw, count]) => parseCampaignSignal(raw, count))
    .sort(compareSignals);
  const groups: CampaignPresentation["groups"] = {
    primary: [],
    destination: [],
    supporting: [],
    technical: [],
    other: [],
  };
  for (const signal of signals) groups[signal.group].push(signal);

  const threat = firstUseful(signals, "threat");
  const scenario = firstUseful(signals, "scenario");
  const action = firstUseful(signals, "action");
  const brand = firstUseful(signals, "brand");
  const domain = firstUseful(signals, "domain");

  let title = "Cụm tín hiệu bảo mật cần duyệt";
  if (threat) title = `Nghi vấn ${lowerFirst(threat.label)}`;
  else if (scenario) title = `Nghi vấn trong bối cảnh ${lowerFirst(scenario.label)}`;
  else if (action) title = `Cụm liên quan đến ${lowerFirst(action.label)}`;
  else if (domain) title = `Cụm tín hiệu liên quan đến ${domain.label}`;

  const subtitle = brand
    ? `Liên quan đến ${brand.label}`
    : domain && !title.includes(domain.label)
      ? `Domain nổi bật: ${domain.label}`
      : null;
  const readableSignals = signals.filter((signal) =>
    ["threat", "scenario", "action", "brand", "domain", "redirect"].includes(signal.prefix)
    && signal.value.toLocaleLowerCase("en-US") !== "unknown"
    && signal.value.toLocaleLowerCase("en-US") !== "undetermined_security_threat"
  );
  const summary = [
    `Cụm gồm ${record.analysis_ids.length} phân tích trong khoảng ${formatDuration(record.window_started_at, record.window_ended_at)}.`,
    ...readableSignals.slice(0, 3).map((signal) => describeSignal(signal, record.analysis_ids.length)),
  ];
  if (readableSignals.length === 0) {
    summary.push("Các tín hiệu chung hiện chỉ có dữ liệu kỹ thuật; cần mở chi tiết để đối chiếu thêm.");
  }

  const topSignals = [...groups.primary, ...groups.destination]
    .filter((signal) =>
      signal.value.toLocaleLowerCase("en-US") !== "unknown"
      && signal.value.toLocaleLowerCase("en-US") !== "undetermined_security_threat"
    )
    .slice(0, 3);

  return { title, subtitle, summary, topSignals, groups };
}
