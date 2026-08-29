import { z } from "zod";

import type { components } from "../contracts/v4.generated";
import type { TrustGuardApiConfig } from "./config";

export type SecurityConsent = components["schemas"]["SecurityConsentV4"];
export type SecurityTriageCreateRequest = components["schemas"]["SecurityTriageCreateRequestV4"];
export type AnalysisStatus = components["schemas"]["AnalysisStatus"];
export type SecurityRisk = components["schemas"]["SecurityRiskV4"];
export type ScopeDecision = components["schemas"]["ScopeDecisionV4"];
export type RecommendedAction = components["schemas"]["SecurityRecommendedActionV4"];

const riskSchema = z.enum([
  "SAFE",
  "LOW_RISK",
  "SUSPICIOUS",
  "HIGH_RISK",
  "MALICIOUS",
  "INSUFFICIENT_EVIDENCE",
]);

const scopeDecisionSchema = z.enum([
  "IN_SCOPE",
  "NEED_MORE_INFO",
  "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
]);

const recommendedActionSchema = z.enum([
  "DO_NOT_OPEN_LINK",
  "DO_NOT_SHARE_CREDENTIALS",
  "DO_NOT_SHARE_OTP",
  "DO_NOT_TRANSFER_MONEY",
  "VERIFY_VIA_OFFICIAL_CHANNEL",
  "CHANGE_PASSWORD_IF_ALREADY_SHARED",
  "CONTACT_BANK_IF_ALREADY_PAID",
  "REPORT_AND_BLOCK_SENDER",
  "PROCEED_WITH_CAUTION",
  "ALLOW_OPEN",
  "CLOSE_PAGE_AND_DO_NOT_RETURN",
  "CHANGE_PASSWORD_FROM_TRUSTED_DEVICE",
  "REVOKE_ACTIVE_SESSIONS",
  "CONTACT_BANK_OR_PAYMENT_PROVIDER",
  "PRESERVE_MESSAGE_FOR_REPORTING",
]);

const boundedText = (maximum: number) => z.string().transform((value) => value.slice(0, maximum));

const capabilitiesSchema = z.object({
  security_async_execution: z.literal(true).nullable().optional(),
}).passthrough();

const acceptedResponseSchema = z.object({
  contract_version: z.literal("v4"),
  analysis_id: z.uuid(),
  conversation_id: z.uuid(),
  conversation_version: z.number().int().positive(),
  status: z.literal("queued"),
  created_at: z.iso.datetime({ offset: true }),
}).passthrough();

const inlineResponseSchema = z.object({
  contract_version: z.literal("v4"),
  analysis_id: z.uuid(),
  conversation_id: z.uuid(),
  conversation_version: z.number().int().positive(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  scope_decision: z.enum(["IN_SCOPE", "NEED_MORE_INFO", "OUT_OF_SCOPE_GENERAL_FACT_CHECK"]),
  terminal: z.boolean(),
  created_at: z.iso.datetime({ offset: true }),
}).passthrough();

const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    retryable: z.boolean(),
  }).passthrough(),
}).passthrough();

const analysisEventSchema = z.object({
  event_id: z.uuid(),
  analysis_id: z.uuid(),
  sequence: z.number().int().positive(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  step: z.string().min(1).max(200),
  kind: z.enum(["status", "provisional", "progress", "final"]),
  progress_state: z.enum(["started", "completed", "skipped", "degraded"]).nullable().optional(),
  occurred_at: z.iso.datetime({ offset: true }),
}).passthrough();

const eventPageSchema = z.object({
  contract_version: z.literal("v4"),
  events: z.array(analysisEventSchema).max(500),
  next_cursor: z.string().max(128).nullable().optional(),
}).passthrough();

const webSocketTicketSchema = z.object({
  contract_version: z.literal("v4"),
  ticket: z.string().min(1).max(256),
  analysis_id: z.uuid(),
  expires_at: z.iso.datetime({ offset: true }),
  stream_path: z.string().min(1).max(300),
  single_use: z.literal(true),
}).passthrough();

const analysisSnapshotSchema = z.object({
  contract_version: z.literal("v4"),
  analysis_id: z.uuid(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  terminal: z.boolean(),
  created_at: z.iso.datetime({ offset: true }),
  scope_decision: scopeDecisionSchema,
  risk: riskSchema.nullable().optional(),
  score: z.number().int().min(0).max(100).nullable().optional(),
  confidence: z.number().min(0).max(1).nullable().optional(),
  explanation: boundedText(2_000).nullable().optional(),
  follow_up_question: boundedText(1_000).nullable().optional(),
  boundary_message: boundedText(1_000).nullable().optional(),
  limitations: z.array(boundedText(1_000)).max(100).optional(),
  recommended_actions: z.array(recommendedActionSchema).max(20).optional(),
  errors: z.array(z.object({
    code: z.string().regex(/^[A-Z0-9_]+$/u),
  }).passthrough()).max(100).optional(),
  assistant_response: z.object({
    summary: z.string().min(1).max(2_000),
    immediate_steps: z.array(z.object({
      action: recommendedActionSchema,
    }).passthrough()).min(1).max(20),
    degradation_reason: z.string().max(100).nullable().optional(),
  }).passthrough().nullable().optional(),
}).passthrough();

export type SubmissionErrorCode =
  | "not_configured"
  | "reauth_required"
  | "forbidden"
  | "validation"
  | "rate_limited"
  | "conflict"
  | "timeout"
  | "offline"
  | "server_error"
  | "invalid_response"
  | "stale_capture"
  | "stale_analysis"
  | "storage_error";

export class TrustGuardApiError extends Error {
  constructor(
    readonly code: SubmissionErrorCode,
    readonly retryable: boolean,
    readonly status: number,
  ) {
    super(code);
    this.name = "TrustGuardApiError";
  }
}

export interface AnalysisSubmissionResult {
  analysisId: string;
  executionMode: "inline" | "async";
  status: AnalysisStatus;
  createdAt: string;
}

export interface AnalysisEvent {
  eventId: string;
  analysisId: string;
  sequence: number;
  status: AnalysisStatus;
  step: string;
  kind: "status" | "provisional" | "progress" | "final";
  progressState: "started" | "completed" | "skipped" | "degraded" | null;
  occurredAt: string;
}

export interface AnalysisEventPage {
  events: AnalysisEvent[];
  nextCursor: string | null;
}

export interface WebSocketTicket {
  ticket: string;
  analysisId: string;
  expiresAt: string;
  streamPath: string;
}

export interface AnalysisSnapshot {
  analysisId: string;
  status: AnalysisStatus;
  terminal: boolean;
  createdAt: string;
  result: AnalysisFinalResult | null;
}

export interface AnalysisFinalResult {
  scopeDecision: ScopeDecision;
  risk: SecurityRisk | null;
  score: number | null;
  confidence: number | null;
  summary: string | null;
  followUpQuestion: string | null;
  boundaryMessage: string | null;
  limitations: string[];
  recommendedActions: RecommendedAction[];
  degraded: boolean;
}

export interface TrustGuardAnalysisApi {
  getCapabilities(): Promise<{ securityAsyncExecution: boolean }>;
  createAnalysis(
    request: SecurityTriageCreateRequest,
    accessToken: string,
    idempotencyKey: string,
  ): Promise<AnalysisSubmissionResult>;
}

export interface TrustGuardProgressApi {
  createWebSocketTicket(analysisId: string, accessToken: string): Promise<WebSocketTicket>;
  getAnalysisEvents(analysisId: string, cursor: string | null, accessToken: string): Promise<AnalysisEventPage>;
  getAnalysis(analysisId: string, accessToken: string): Promise<AnalysisSnapshot>;
}

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const DEFAULT_TIMEOUT_MS = 75_000;

function errorForStatus(status: number, retryable: boolean): TrustGuardApiError {
  if (status === 401) return new TrustGuardApiError("reauth_required", false, status);
  if (status === 403) return new TrustGuardApiError("forbidden", false, status);
  if (status === 409) return new TrustGuardApiError("conflict", false, status);
  if (status === 422) return new TrustGuardApiError("validation", false, status);
  if (status === 429) return new TrustGuardApiError("rate_limited", true, status);
  return new TrustGuardApiError("server_error", retryable || status >= 500, status);
}

export class HttpTrustGuardAnalysisApi implements TrustGuardAnalysisApi, TrustGuardProgressApi {
  private readonly fetcher: Fetcher;
  private readonly timeoutMs: number;

  constructor(
    private readonly config: TrustGuardApiConfig,
    options: { fetcher?: Fetcher; timeoutMs?: number } = {},
  ) {
    this.fetcher = options.fetcher ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetcher(`${this.config.baseUrl}/api/v4/${path}`, {
        ...init,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
    } catch {
      throw new TrustGuardApiError(controller.signal.aborted ? "timeout" : "offline", true, 0);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async json(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      throw new TrustGuardApiError("invalid_response", response.status >= 500, response.status);
    }
  }

  private async requireOk(response: Response): Promise<unknown> {
    const payload = await this.json(response);
    if (response.ok) return payload;
    const parsed = errorEnvelopeSchema.safeParse(payload);
    throw errorForStatus(response.status, parsed.success ? parsed.data.error.retryable : response.status >= 500);
  }

  async getCapabilities(): Promise<{ securityAsyncExecution: boolean }> {
    const response = await this.request("capabilities", {
      headers: { Accept: "application/json" },
    });
    const parsed = capabilitiesSchema.safeParse(await this.requireOk(response));
    if (!parsed.success) throw new TrustGuardApiError("invalid_response", false, response.status);
    return { securityAsyncExecution: parsed.data.security_async_execution === true };
  }

  async createAnalysis(
    request: SecurityTriageCreateRequest,
    accessToken: string,
    idempotencyKey: string,
  ): Promise<AnalysisSubmissionResult> {
    const response = await this.request("analyses", {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(request),
    });
    const payload = await this.requireOk(response);
    if (response.status === 202) {
      const parsed = acceptedResponseSchema.safeParse(payload);
      if (!parsed.success) throw new TrustGuardApiError("invalid_response", false, response.status);
      return {
        analysisId: parsed.data.analysis_id,
        executionMode: "async",
        status: parsed.data.status,
        createdAt: parsed.data.created_at,
      };
    }
    if (response.status === 200) {
      const parsed = inlineResponseSchema.safeParse(payload);
      if (!parsed.success) throw new TrustGuardApiError("invalid_response", false, response.status);
      return {
        analysisId: parsed.data.analysis_id,
        executionMode: "inline",
        status: parsed.data.status,
        createdAt: parsed.data.created_at,
      };
    }
    throw new TrustGuardApiError("invalid_response", false, response.status);
  }

  async createWebSocketTicket(analysisId: string, accessToken: string): Promise<WebSocketTicket> {
    const response = await this.request("ws-tickets", {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ analysis_id: analysisId }),
    });
    const parsed = webSocketTicketSchema.safeParse(await this.requireOk(response));
    if (!parsed.success || parsed.data.analysis_id !== analysisId) {
      throw new TrustGuardApiError("invalid_response", false, response.status);
    }
    return {
      ticket: parsed.data.ticket,
      analysisId: parsed.data.analysis_id,
      expiresAt: parsed.data.expires_at,
      streamPath: parsed.data.stream_path,
    };
  }

  async getAnalysisEvents(
    analysisId: string,
    cursor: string | null,
    accessToken: string,
  ): Promise<AnalysisEventPage> {
    const query = new URLSearchParams({ limit: "100" });
    if (cursor !== null) query.set("cursor", cursor);
    const response = await this.request(`analyses/${analysisId}/events?${query.toString()}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const parsed = eventPageSchema.safeParse(await this.requireOk(response));
    if (!parsed.success) {
      throw new TrustGuardApiError("invalid_response", false, response.status);
    }
    return {
      events: parsed.data.events.filter((event) => event.analysis_id === analysisId).map((event) => ({
        eventId: event.event_id,
        analysisId: event.analysis_id,
        sequence: event.sequence,
        status: event.status,
        step: event.step,
        kind: event.kind,
        progressState: event.progress_state ?? null,
        occurredAt: event.occurred_at,
      })),
      nextCursor: parsed.data.next_cursor ?? cursor,
    };
  }

  async getAnalysis(analysisId: string, accessToken: string): Promise<AnalysisSnapshot> {
    const response = await this.request(`analyses/${analysisId}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
    });
    const parsed = analysisSnapshotSchema.safeParse(await this.requireOk(response));
    if (!parsed.success || parsed.data.analysis_id !== analysisId) {
      throw new TrustGuardApiError("invalid_response", false, response.status);
    }
    return {
      analysisId: parsed.data.analysis_id,
      status: parsed.data.status,
      terminal: parsed.data.terminal,
      createdAt: parsed.data.created_at,
      result: parsed.data.terminal ? {
        scopeDecision: parsed.data.scope_decision,
        risk: parsed.data.risk ?? null,
        score: parsed.data.score ?? null,
        confidence: parsed.data.confidence ?? null,
        summary: parsed.data.assistant_response?.summary ?? parsed.data.explanation ?? null,
        followUpQuestion: parsed.data.follow_up_question ?? null,
        boundaryMessage: parsed.data.boundary_message ?? null,
        limitations: (parsed.data.limitations ?? []).slice(0, 3),
        recommendedActions: (
          parsed.data.assistant_response?.immediate_steps.map((step) => step.action) ??
          parsed.data.recommended_actions ??
          []
        ).slice(0, 5),
        degraded:
          (parsed.data.errors?.length ?? 0) > 0 ||
          Boolean(parsed.data.assistant_response?.degradation_reason),
      } : null,
    };
  }
}
