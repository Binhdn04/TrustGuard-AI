"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopySafeValue({ value, label = "URL" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <span className="flex min-w-0 items-start gap-2 rounded-lg border border-border bg-muted/50 p-2">
      <code className="min-w-0 flex-1 break-all text-[11px] leading-5">{value}</code>
      <button
        type="button"
        onClick={() => void copy()}
        aria-label={`Sao chép ${label}`}
        className="grid size-7 shrink-0 place-items-center rounded-md border border-border bg-background text-muted-foreground hover:text-foreground"
      >
        {copied ? <Check className="size-3.5" aria-hidden="true" /> : <Copy className="size-3.5" aria-hidden="true" />}
      </button>
    </span>
  );
}
