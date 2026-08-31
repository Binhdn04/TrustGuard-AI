import type { CaseSignalNode } from "@/lib/mappers/security-case-view-model";

import { securityLabel } from "./security-labels";

export function readableSignalValue(value: string): string {
  if (!value) return "Chưa xác định";
  return value
    .split("+")
    .map((part) => securityLabel(part))
    .join(" · ");
}

export function safeSignalDetail(value: string | null): string | null {
  if (!value) return null;
  if (value === "URL") return "URL được phân tích";
  if (value === "Evidence target") return "Đối tượng của bằng chứng";
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return `${parsed.origin}${parsed.pathname || "/"}`;
    }
  } catch {
    // Non-URL details are labels or source descriptions and are safe to display as provided.
  }
  return readableSignalValue(value);
}

export function presentSignalNode(node: CaseSignalNode): { label: string; detail: string | null } {
  return {
    label: safeSignalDetail(node.label) ?? readableSignalValue(node.label),
    detail: safeSignalDetail(node.detail),
  };
}
