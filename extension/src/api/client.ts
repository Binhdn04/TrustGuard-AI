import { z } from "zod";

import type { components } from "../contracts/v4.generated";
import type { TrustGuardApiConfig } from "./config";

export type SecurityConsent = components["schemas"]["SecurityConsentV4"];
export type SecurityTriageCreateRequest = components["schemas"]["SecurityTriageCreateRequestV4"];
export type AnalysisStatus = components["schemas"]["AnalysisStatus"];

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
    };
  }
}
