"use client";

import { useState, type FormEvent } from "react";
import { Filter, Search } from "lucide-react";

import type { SecurityHistoryQuery } from "@/lib/mappers/security-history-query";
import type { SecurityRiskV4, SecurityScopeDecisionV4 } from "@/types/generated/api-v4";

const riskOptions: Array<{ value: SecurityRiskV4; label: string }> = [
  { value: "MALICIOUS", label: "Nguy hiểm" },
  { value: "HIGH_RISK", label: "Rủi ro cao" },
  { value: "SUSPICIOUS", label: "Đáng ngờ" },
  { value: "LOW_RISK", label: "Rủi ro thấp" },
  { value: "SAFE", label: "Chưa phát hiện rủi ro" },
  { value: "INSUFFICIENT_EVIDENCE", label: "Chưa đủ bằng chứng" },
];

export function CaseListFilters({
  query,
  disabled,
  onChange,
}: {
  query: SecurityHistoryQuery;
  disabled: boolean;
  onChange(query: SecurityHistoryQuery): void;
}) {
  const [draft, setDraft] = useState(query.q);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onChange({ ...query, q: draft.trim().slice(0, 200), page: 1 });
  };

  return (
    <form onSubmit={submit} role="search" className="grid gap-3 lg:grid-cols-[minmax(16rem,1fr)_13rem_14rem_auto]">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <input
          aria-label="Tìm theo thực thể hoặc URL"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          maxLength={200}
          placeholder="Thực thể hoặc URL…"
          className="w-full rounded-xl border border-input bg-background py-2.5 pl-9 pr-4 text-sm"
        />
      </div>
      <select
        aria-label="Lọc theo quyết định phạm vi"
        value={query.scopeDecision ?? ""}
        disabled={disabled}
        onChange={(event) => onChange({
          ...query,
          scopeDecision: event.target.value ? event.target.value as SecurityScopeDecisionV4 : null,
          page: 1,
        })}
        className="w-full rounded-xl border border-input bg-background px-3 py-2.5 text-sm disabled:opacity-60"
      >
        <option value="">Tất cả quyết định</option>
        <option value="IN_SCOPE">Trong phạm vi</option>
        <option value="NEED_MORE_INFO">Cần thêm thông tin</option>
        <option value="OUT_OF_SCOPE_GENERAL_FACT_CHECK">Ngoài phạm vi</option>
      </select>
      <div className="relative">
        <Filter className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <select
          aria-label="Lọc theo mức rủi ro"
          value={query.risk ?? ""}
          disabled={disabled}
          onChange={(event) => onChange({
            ...query,
            risk: event.target.value ? event.target.value as SecurityRiskV4 : null,
            page: 1,
          })}
          className="w-full rounded-xl border border-input bg-background py-2.5 pl-9 pr-3 text-sm disabled:opacity-60"
        >
          <option value="">Tất cả mức rủi ro</option>
          {riskOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </div>
      <button
        type="submit"
        disabled={disabled}
        className="rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60"
      >
        Tìm case
      </button>
    </form>
  );
}
