import type {
  AssistantReasonV4,
  SecurityAnalysisEventV4,
  SecurityEvidenceV4,
  SecurityRecommendedActionV4,
  SecurityRiskV4,
  SecurityScopeResponseV4,
} from "@/types/generated/api-v4";
import { riskLabel } from "@/lib/presentation/security-labels";

export type SecurityPresentationMode = "simple" | "analyst";
export type CaseSignalNodeKind = "context" | "target" | "action" | "threat" | "step" | "evidence" | "decision";

export interface CaseSignalNode {
  id: string;
  kind: CaseSignalNodeKind;
  label: string;
  detail: string | null;
  sourceRef: string;
}

export interface CaseSignalEdge {
  id: string;
  from: string;
  to: string;
  relation: "requested_action" | "context_url" | "potential_threat" | "depends_on" | "evidence_target" | "used_in_decision";
  sourceRef: string;
}

export interface CaseEvidenceCard {
  evidence: SecurityEvidenceV4;
  usedInDecision: boolean;
}

export interface CaseLifecycleEntry {
  id: string;
  label: string;
  status: SecurityAnalysisEventV4["status"];
  occurredAt: string;
  sequence: number | null;
  source: "event" | "analysis";
}

export interface SecurityCaseViewModel {
  risk: {
    value: SecurityRiskV4 | null;
    label: string;
    tone: "safe" | "caution" | "danger" | "neutral";
    score: number | null;
    confidence: number | null;
    threatType: string | null;
    explanation: string | null;
  };
  actions: Array<{ code: SecurityRecommendedActionV4; label: string; policyRef: string | null }>;
  assistant: {
    summary: string;
    topReasons: AssistantReasonV4[];
    uncertainties: string[];
    followUpOffer: string | null;
    responseVersion: string;
    generationMode: "ai" | "policy_grounded" | "template_fallback";
  } | null;
  signalNodes: CaseSignalNode[];
  signalEdges: CaseSignalEdge[];
  evidence: CaseEvidenceCard[];
  lifecycle: CaseLifecycleEntry[];
  steps: SecurityScopeResponseV4["investigation_plan"];
  errors: SecurityScopeResponseV4["errors"];
  context: SecurityScopeResponseV4["security_context"];
  officialVerification: SecurityScopeResponseV4["official_verification"];
  policyVersion: string | null;
}

export const SECURITY_ACTION_LABELS: Record<SecurityRecommendedActionV4, string> = {
  DO_NOT_OPEN_LINK: "Không mở liên kết",
  DO_NOT_SHARE_CREDENTIALS: "Không cung cấp thông tin đăng nhập",
  DO_NOT_SHARE_OTP: "Không chia sẻ mã OTP",
  DO_NOT_TRANSFER_MONEY: "Không chuyển tiền",
  VERIFY_VIA_OFFICIAL_CHANNEL: "Tự liên hệ qua kênh chính thức",
  CHANGE_PASSWORD_IF_ALREADY_SHARED: "Đổi mật khẩu nếu đã cung cấp",
  CONTACT_BANK_IF_ALREADY_PAID: "Liên hệ ngân hàng nếu đã chuyển tiền",
  REPORT_AND_BLOCK_SENDER: "Báo cáo và chặn người gửi",
  PROCEED_WITH_CAUTION: "Tiếp tục thận trọng",
  CLOSE_PAGE_AND_DO_NOT_RETURN: "Đóng trang và không quay lại",
  CHANGE_PASSWORD_FROM_TRUSTED_DEVICE: "Đổi mật khẩu trên thiết bị tin cậy",
  REVOKE_ACTIVE_SESSIONS: "Thu hồi các phiên đăng nhập đang hoạt động",
  CONTACT_BANK_OR_PAYMENT_PROVIDER: "Liên hệ ngay ngân hàng hoặc đơn vị thanh toán",
  PRESERVE_MESSAGE_FOR_REPORTING: "Lưu lại tin nhắn để báo cáo",
};

const RISK_TONE: Record<SecurityRiskV4, SecurityCaseViewModel["risk"]["tone"]> = {
  SAFE: "safe",
  LOW_RISK: "safe",
  SUSPICIOUS: "caution",
  HIGH_RISK: "danger",
  MALICIOUS: "danger",
  INSUFFICIENT_EVIDENCE: "neutral",
};

function targetId(target: string): string {
  return `target:${encodeURIComponent(target)}`;
}

function pushNode(nodes: CaseSignalNode[], known: Set<string>, node: CaseSignalNode) {
  if (known.has(node.id)) return;
  known.add(node.id);
  nodes.push(node);
}

function lifecycleFrom(
  result: SecurityScopeResponseV4,
  events: SecurityAnalysisEventV4[],
): CaseLifecycleEntry[] {
  const actualEvents = events
    .filter((event) => event.analysis_id === result.analysis_id)
    .sort((left, right) => left.sequence - right.sequence);
  if (actualEvents.length > 0) {
    return actualEvents.map((event) => ({
      id: event.event_id,
      label: event.step,
      status: event.status,
      occurredAt: event.occurred_at,
      sequence: event.sequence,
      source: "event",
    }));
  }

  const lifecycle: CaseLifecycleEntry[] = [{
    id: `${result.analysis_id}:created`,
    label: "analysis_created",
    status: result.status === "queued" ? "queued" : "running",
    occurredAt: result.created_at,
    sequence: null,
    source: "analysis",
  }];
  if (result.completed_at) {
    lifecycle.push({
      id: `${result.analysis_id}:completed`,
      label: result.status === "failed" ? "analysis_failed" : "analysis_completed",
      status: result.status,
      occurredAt: result.completed_at,
      sequence: null,
      source: "analysis",
    });
  }
  return lifecycle;
}

export function mapSecurityCaseViewModel(
  result: SecurityScopeResponseV4,
  events: SecurityAnalysisEventV4[] = [],
): SecurityCaseViewModel {
  const nodes: CaseSignalNode[] = [];
  const edges: CaseSignalEdge[] = [];
  const knownNodes = new Set<string>();
  const context = result.security_context;

  if (context) {
    pushNode(nodes, knownNodes, {
      id: "context",
      kind: "context",
      label: context.claimed_entity ?? context.scenario,
      detail: context.scenario,
      sourceRef: "security_context",
    });
    if (context.requested_action) {
      const id = `action:${context.requested_action}`;
      pushNode(nodes, knownNodes, {
        id,
        kind: "action",
        label: context.requested_action,
        detail: context.amount,
        sourceRef: "security_context.requested_action",
      });
      edges.push({ id: `context->${id}`, from: "context", to: id, relation: "requested_action", sourceRef: "security_context.requested_action" });
    }
    for (const url of context.urls) {
      const id = targetId(url);
      pushNode(nodes, knownNodes, { id, kind: "target", label: url, detail: "URL", sourceRef: "security_context.urls" });
      edges.push({ id: `context->${id}`, from: "context", to: id, relation: "context_url", sourceRef: "security_context.urls" });
    }
    const threatId = `threat:${context.potential_threat}`;
    pushNode(nodes, knownNodes, {
      id: threatId,
      kind: "threat",
      label: context.potential_threat,
      detail: null,
      sourceRef: "security_context.potential_threat",
    });
    edges.push({ id: `context->${threatId}`, from: "context", to: threatId, relation: "potential_threat", sourceRef: "security_context.potential_threat" });
  }

  const stepIds = new Set(result.investigation_plan.map((step) => step.step_id));
  for (const step of result.investigation_plan) {
    pushNode(nodes, knownNodes, {
      id: step.step_id,
      kind: "step",
      label: step.tool,
      detail: step.target,
      sourceRef: step.step_id,
    });
    for (const dependency of step.depends_on) {
      if (!stepIds.has(dependency)) continue;
      edges.push({
        id: `${dependency}->${step.step_id}`,
        from: dependency,
        to: step.step_id,
        relation: "depends_on",
        sourceRef: `${step.step_id}.depends_on`,
      });
    }
  }

  const usedEvidence = new Set(result.explanation_evidence_refs);
  for (const evidence of result.evidence) {
    pushNode(nodes, knownNodes, {
      id: evidence.evidence_ref,
      kind: "evidence",
      label: evidence.signal,
      detail: evidence.description,
      sourceRef: evidence.evidence_ref,
    });
    if (evidence.target) {
      const id = targetId(evidence.target);
      pushNode(nodes, knownNodes, {
        id,
        kind: "target",
        label: evidence.target,
        detail: "Evidence target",
        sourceRef: `${evidence.evidence_ref}.target`,
      });
      edges.push({
        id: `${id}->${evidence.evidence_ref}`,
        from: id,
        to: evidence.evidence_ref,
        relation: "evidence_target",
        sourceRef: `${evidence.evidence_ref}.target`,
      });
    }
  }

  if (result.risk) {
    pushNode(nodes, knownNodes, {
      id: "decision",
      kind: "decision",
      label: result.risk,
      detail: result.threat_type,
      sourceRef: "risk",
    });
    for (const evidenceRef of result.explanation_evidence_refs) {
      if (!knownNodes.has(evidenceRef)) continue;
      edges.push({
        id: `${evidenceRef}->decision`,
        from: evidenceRef,
        to: "decision",
        relation: "used_in_decision",
        sourceRef: "explanation_evidence_refs",
      });
    }
  }

  const riskPresentation = result.risk
    ? { label: riskLabel(result.risk), tone: RISK_TONE[result.risk] }
    : { label: riskLabel(null), tone: "neutral" as const };

  const assistant = result.assistant_response ?? null;
  const assistantActions = assistant?.immediate_steps ?? [];
  const actions = assistantActions.length > 0
    ? assistantActions.map((step) => ({
        code: step.action,
        label: SECURITY_ACTION_LABELS[step.action],
        policyRef: step.policy_ref,
      }))
    : result.recommended_actions.map((code) => ({
        code,
        label: SECURITY_ACTION_LABELS[code],
        policyRef: result.policy_version,
      }));

  return {
    risk: {
      value: result.risk,
      label: riskPresentation.label,
      tone: riskPresentation.tone,
      score: result.score,
      confidence: result.confidence,
      threatType: result.threat_type,
      explanation: result.explanation,
    },
    actions,
    assistant: assistant ? {
      summary: assistant.summary,
      topReasons: assistant.top_reasons,
      uncertainties: assistant.uncertainties,
      followUpOffer: assistant.follow_up_offer,
      responseVersion: assistant.response_version,
      generationMode: assistant.generation_mode,
    } : null,
    signalNodes: nodes,
    signalEdges: edges,
    evidence: result.evidence.map((evidence) => ({ evidence, usedInDecision: usedEvidence.has(evidence.evidence_ref) })),
    lifecycle: lifecycleFrom(result, events),
    steps: result.investigation_plan,
    errors: result.errors,
    context,
    officialVerification: result.official_verification ?? null,
    policyVersion: result.policy_version,
  };
}
