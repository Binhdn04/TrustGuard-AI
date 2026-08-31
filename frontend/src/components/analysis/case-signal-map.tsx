import { useState } from "react";
import { ChevronDown, CircleDot } from "lucide-react";

import type {
  CaseSignalEdge,
  CaseSignalNode,
  CaseSignalNodeKind,
  SecurityCaseViewModel,
  SecurityPresentationMode,
} from "@/lib/mappers/security-case-view-model";
import { presentSignalNode } from "@/lib/presentation/signal-map-presentation";
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
  step: "border-violet-500/20 bg-violet-500/5",
  evidence: "border-cyan-500/25 bg-cyan-500/8",
  decision: "border-rose-500/25 bg-rose-500/8",
};

function NodeCard({ node, showSource = false, highlighted = false }: {
  node: CaseSignalNode;
  showSource?: boolean;
  highlighted?: boolean;
}) {
  const presentation = presentSignalNode(node);
  return (
    <article className={cn(
      "min-w-0 rounded-xl border p-3",
      kindStyle[node.kind],
      highlighted && "ring-1 ring-primary/35",
    )}>
      <p className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground">{kindLabel[node.kind]}</p>
      <p className="mt-1 break-words text-xs font-semibold" title={presentation.label}>{presentation.label}</p>
      {presentation.detail && <p className="mt-1 break-words text-[10px] leading-4 text-muted-foreground">{presentation.detail}</p>}
      {showSource && (
        <details className="group/source mt-2 border-t border-border/60 pt-2">
          <summary className="flex cursor-pointer list-none items-center justify-between text-[9px] text-muted-foreground">
            Mã nguồn
            <ChevronDown className="size-3 transition-transform group-open/source:rotate-180" />
          </summary>
          <p className="mt-1 break-all font-mono text-[9px] text-muted-foreground">{node.sourceRef}</p>
        </details>
      )}
    </article>
  );
}

function RelationList({ edges, nodeById, hidden = false }: {
  edges: CaseSignalEdge[];
  nodeById: Map<string, CaseSignalNode>;
  hidden?: boolean;
}) {
  return (
    <ul aria-label="Quan hệ giữa các tín hiệu" className={hidden ? "sr-only" : "space-y-2"}>
      {edges.map((edge) => {
        const from = nodeById.get(edge.from);
        const to = nodeById.get(edge.to);
        return (
          <li key={edge.id} className={hidden ? undefined : "rounded-lg border border-border bg-background/45 p-2.5 text-xs"}>
            <span className={hidden ? undefined : "flex items-start gap-2"}>
              {!hidden && <CircleDot className="mt-0.5 size-3 shrink-0 text-primary" />}
              <span>
                {from ? presentSignalNode(from).label : edge.from}
                {" → "}{securityLabel(edge.relation)}{" → "}
                {to ? presentSignalNode(to).label : edge.to}
              </span>
            </span>
            {!hidden && (
              <details className="group/source mt-1 pl-5">
                <summary className="cursor-pointer list-none text-[9px] text-muted-foreground">Xem mã quan hệ</summary>
                <p className="mt-1 break-all font-mono text-[9px] text-muted-foreground">{edge.sourceRef}</p>
              </details>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function OverviewPanel({ nodes, edges, nodeById }: {
  nodes: CaseSignalNode[];
  edges: CaseSignalEdge[];
  nodeById: Map<string, CaseSignalNode>;
}) {
  const contextIds = new Set(nodes.filter((node) => node.kind === "context").map((node) => node.id));
  const inputIds = new Set(contextIds);
  for (const edge of edges) {
    if (
      contextIds.has(edge.from)
      && ["requested_action", "context_url", "potential_threat"].includes(edge.relation)
    ) {
      inputIds.add(edge.to);
    }
  }
  const inputNodes = nodes.filter((node) => inputIds.has(node.id));
  const stepNodes = nodes.filter((node) => node.kind === "step");
  const evidenceNodes = nodes.filter((node) => node.kind === "evidence");
  const usedEvidenceIds = new Set(
    edges.filter((edge) => edge.relation === "used_in_decision").map((edge) => edge.from),
  );
  const usedEvidence = evidenceNodes.filter((node) => usedEvidenceIds.has(node.id));
  const otherEvidence = evidenceNodes.filter((node) => !usedEvidenceIds.has(node.id));
  const decisionNodes = nodes.filter((node) => node.kind === "decision");

  return (
    <div id="signal-map-overview-panel" role="tabpanel" aria-labelledby="signal-map-overview-tab" className="mt-4 space-y-4">
      <section>
        <h4 className="micro-label">Thông tin đầu vào</h4>
        {inputNodes.length > 0 ? (
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {inputNodes.map((node) => <NodeCard key={node.id} node={node} />)}
          </div>
        ) : (
          <p className="mt-2 rounded-xl border border-dashed border-border p-3 text-xs text-muted-foreground">
            Không có ngữ cảnh hoặc đối tượng có cấu trúc.
          </p>
        )}
      </section>

      <section>
        <div className="flex items-center justify-between gap-3">
          <h4 className="micro-label">Bằng chứng dùng trong kết luận</h4>
          <span className="text-[10px] text-muted-foreground">{usedEvidence.length}/{evidenceNodes.length} bằng chứng</span>
        </div>
        {usedEvidence.length > 0 ? (
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {usedEvidence.map((node) => <NodeCard key={node.id} node={node} highlighted />)}
          </div>
        ) : (
          <p className="mt-2 rounded-xl border border-dashed border-border p-3 text-xs text-muted-foreground">
            Kết luận không tham chiếu bằng chứng nào trong dữ liệu được trả về.
          </p>
        )}
      </section>

      {decisionNodes.length > 0 && (
        <section>
          <h4 className="micro-label">Kết luận được trả về</h4>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {decisionNodes.map((node) => <NodeCard key={node.id} node={node} highlighted />)}
          </div>
        </section>
      )}

      {stepNodes.length > 0 && (
        <details className="group rounded-xl border border-border p-3">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold">
            <span>{stepNodes.length} bước kiểm tra được ghi nhận</span>
            <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" />
          </summary>
          <div className="mt-3 grid gap-2 border-t border-border pt-3 sm:grid-cols-2">
            {stepNodes.map((node) => <NodeCard key={node.id} node={node} />)}
          </div>
        </details>
      )}

      {otherEvidence.length > 0 && (
        <details className="group rounded-xl border border-border p-3">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold">
            <span>{otherEvidence.length} bằng chứng bổ sung</span>
            <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" />
          </summary>
          <div className="mt-3 grid gap-2 border-t border-border pt-3 sm:grid-cols-2">
            {otherEvidence.map((node) => <NodeCard key={node.id} node={node} />)}
          </div>
        </details>
      )}

      <RelationList edges={edges} nodeById={nodeById} hidden />
    </div>
  );
}

const technicalGroups: Array<{ label: string; kinds: CaseSignalNodeKind[] }> = [
  { label: "Ngữ cảnh và đối tượng", kinds: ["context", "target", "action", "threat"] },
  { label: "Các bước kiểm tra", kinds: ["step"] },
  { label: "Bằng chứng", kinds: ["evidence"] },
  { label: "Kết luận", kinds: ["decision"] },
];

function TechnicalPanel({ nodes, edges, nodeById }: {
  nodes: CaseSignalNode[];
  edges: CaseSignalEdge[];
  nodeById: Map<string, CaseSignalNode>;
}) {
  return (
    <div id="signal-map-technical-panel" role="tabpanel" aria-labelledby="signal-map-technical-tab" className="mt-4 space-y-3">
      {technicalGroups.map((group, index) => {
        const groupNodes = nodes.filter((node) => group.kinds.includes(node.kind));
        if (groupNodes.length === 0) return null;
        return (
          <details key={group.label} open={index === 0 || group.label === "Kết luận"} className="group rounded-xl border border-border p-3">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold">
              <span>{group.label} <span className="font-normal text-muted-foreground">({groupNodes.length})</span></span>
              <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" />
            </summary>
            <div className="mt-3 grid gap-2 border-t border-border pt-3 sm:grid-cols-2 xl:grid-cols-3">
              {groupNodes.map((node) => <NodeCard key={node.id} node={node} showSource />)}
            </div>
          </details>
        );
      })}

      {edges.length > 0 && (
        <details className="group rounded-xl border border-border p-3">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold">
            <span>Quan hệ có nguồn <span className="font-normal text-muted-foreground">({edges.length})</span></span>
            <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" />
          </summary>
          <div className="mt-3 border-t border-border pt-3">
            <RelationList edges={edges} nodeById={nodeById} />
          </div>
        </details>
      )}
    </div>
  );
}

export function CaseSignalMap({
  nodes,
  edges,
  mode,
}: {
  nodes: SecurityCaseViewModel["signalNodes"];
  edges: SecurityCaseViewModel["signalEdges"];
  mode: SecurityPresentationMode;
}) {
  const [view, setView] = useState<"overview" | "technical">("overview");
  const activeView = mode === "simple" ? "overview" : view;
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const stepCount = nodes.filter((node) => node.kind === "step").length;
  const evidenceCount = nodes.filter((node) => node.kind === "evidence").length;
  const usedEvidenceCount = new Set(
    edges.filter((edge) => edge.relation === "used_in_decision").map((edge) => edge.from),
  ).size;

  return (
    <section aria-labelledby="signal-map-heading">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="micro-label">Bản đồ tín hiệu</p>
          <h3 id="signal-map-heading" className="mt-1 text-sm font-semibold">Các lớp dữ liệu có nguồn</h3>
        </div>
        <span className="text-[10px] text-muted-foreground">
          {stepCount} bước kiểm tra · {evidenceCount} bằng chứng · {usedEvidenceCount} dùng trong kết luận
        </span>
      </div>

      {nodes.length === 0 ? (
        <p className="mt-3 rounded-xl border border-dashed border-border p-4 text-xs text-muted-foreground">
          Không có tín hiệu có cấu trúc để dựng bản đồ.
        </p>
      ) : (
        <>
          {mode === "analyst" && (
            <div role="tablist" aria-label="Mức chi tiết của bản đồ tín hiệu" className="mt-3 inline-flex rounded-lg border border-border bg-muted/50 p-1">
              <button
                id="signal-map-overview-tab"
                type="button"
                role="tab"
                aria-selected={activeView === "overview"}
                aria-controls="signal-map-overview-panel"
                onClick={() => setView("overview")}
                className={cn("rounded-md px-3 py-1.5 text-xs font-semibold", activeView === "overview" ? "bg-background shadow-sm" : "text-muted-foreground")}
              >
                Tổng quan
              </button>
              <button
                id="signal-map-technical-tab"
                type="button"
                role="tab"
                aria-selected={activeView === "technical"}
                aria-controls="signal-map-technical-panel"
                onClick={() => setView("technical")}
                className={cn("rounded-md px-3 py-1.5 text-xs font-semibold", activeView === "technical" ? "bg-background shadow-sm" : "text-muted-foreground")}
              >
                Toàn bộ kỹ thuật
              </button>
            </div>
          )}

          {activeView === "overview"
            ? <OverviewPanel nodes={nodes} edges={edges} nodeById={nodeById} />
            : <TechnicalPanel nodes={nodes} edges={edges} nodeById={nodeById} />}
        </>
      )}
    </section>
  );
}
