import { ArrowRight, CircleDot } from "lucide-react";

import type {
  CaseSignalNodeKind,
  SecurityCaseViewModel,
  SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import { securityLabel } from "@/lib/presentation/security-labels";
import { cn } from "@/lib/utils";

const kindLabel: Record<CaseSignalNodeKind, string> = {
  context: "Ngữ cảnh",
  target: "Đối tượng",
  action: "Hành động được yêu cầu",
  threat: "Nguy cơ tiềm ẩn",
  step: "Bước kiểm tra",
  evidence: "Bằng chứng",
  decision: "Kết luận",
};

const kindStyle: Record<CaseSignalNodeKind, string> = {
  context: "border-slate-500/25 bg-slate-500/8",
  target: "border-blue-500/25 bg-blue-500/8",
  action: "border-amber-500/25 bg-amber-500/8",
  threat: "border-orange-500/25 bg-orange-500/8",
  step: "border-violet-500/25 bg-violet-500/8",
  evidence: "border-cyan-500/25 bg-cyan-500/8",
  decision: "border-rose-500/25 bg-rose-500/8",
};

export function CaseSignalMap({
  nodes,
  edges,
  mode,
}: {
  nodes: SecurityCaseViewModel["signalNodes"];
  edges: SecurityCaseViewModel["signalEdges"];
  mode: SecurityPresentationMode;
}) {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  return (
    <section aria-labelledby="signal-map-heading">
      <div className="flex items-end justify-between gap-3">
        <div>
          <p className="micro-label">Bản đồ tín hiệu</p>
          <h3 id="signal-map-heading" className="mt-1 text-sm font-semibold">Quan hệ gắn với nguồn</h3>
        </div>
        <span className="text-[10px] text-muted-foreground">{nodes.length} nút · {edges.length} quan hệ</span>
      </div>

      {nodes.length === 0 ? (
        <p className="mt-3 rounded-xl border border-dashed border-border p-4 text-xs text-muted-foreground">Không có tín hiệu có cấu trúc để dựng bản đồ.</p>
      ) : (
        <>
          <div aria-hidden="true" className="mt-3 hidden space-y-3 md:block">
            <div className="grid grid-cols-2 gap-2 xl:grid-cols-3">
              {nodes.map((node) => (
                <div key={node.id} className={cn("min-w-0 rounded-xl border p-3", kindStyle[node.kind])}>
                  <p className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground">{kindLabel[node.kind]}</p>
                  <p className="mt-1 truncate text-xs font-semibold" title={node.label}>{securityLabel(node.label)}</p>
                  {node.detail && <p className="mt-1 truncate text-[10px] text-muted-foreground" title={node.detail}>{node.detail}</p>}
                  {mode === "analyst" && <p className="mt-2 truncate font-mono text-[9px] text-muted-foreground" title={node.sourceRef}>{node.sourceRef}</p>}
                </div>
              ))}
            </div>
            {edges.length > 0 && (
              <div className="rounded-xl border border-border/70 bg-background/45 p-3">
                <p className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground">Quan hệ đã ghi nhận</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {edges.map((edge) => (
                    <span key={edge.id} className="inline-flex max-w-full items-center gap-1 rounded-full border border-border bg-card px-2 py-1 text-[9px]">
                      <span className="max-w-20 truncate">{nodeById.get(edge.from)?.label}</span>
                      <ArrowRight className="size-3 text-primary" />
                      <span className="font-semibold">{securityLabel(edge.relation)}</span>
                      <ArrowRight className="size-3 text-primary" />
                      <span className="max-w-20 truncate">{nodeById.get(edge.to)?.label}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-3 md:sr-only">
            <ul aria-label="Các nút tín hiệu" className="space-y-2">
              {nodes.map((node) => (
                <li key={node.id} className="rounded-lg border border-border p-3 text-xs">
                  <span className="font-semibold">{kindLabel[node.kind]}: {node.label}</span>
                  {node.detail && <span> — {node.detail}</span>}
                  {mode === "analyst" && <span> — nguồn {node.sourceRef}</span>}
                </li>
              ))}
            </ul>
            {edges.length > 0 && (
              <ul aria-label="Quan hệ giữa các tín hiệu" className="mt-3 space-y-1 text-xs">
                {edges.map((edge) => (
                  <li key={edge.id} className="flex items-start gap-2">
                    <CircleDot className="mt-0.5 size-3 shrink-0 text-primary" />
                    {nodeById.get(edge.from)?.label} → {securityLabel(edge.relation)} → {nodeById.get(edge.to)?.label}
                    {mode === "analyst" && ` (nguồn ${edge.sourceRef})`}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}
    </section>
  );
}
