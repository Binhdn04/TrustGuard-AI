import { z } from "zod";

import { authPublicStateSchema } from "../auth/public-state";

export const MAX_CAPTURE_CHARACTERS = 5_000;

export const submissionErrorCodeSchema = z.enum([
  "not_configured",
  "reauth_required",
  "forbidden",
  "validation",
  "rate_limited",
  "conflict",
  "timeout",
  "offline",
  "server_error",
  "invalid_response",
  "stale_capture",
  "stale_analysis",
  "storage_error",
]);

export const activeAnalysisPublicSchema = z.object({
  analysisId: z.uuid(),
  executionMode: z.enum(["inline", "async"]),
  status: z.enum(["queued", "running", "completed", "failed"]),
  cursor: z.string().max(128).nullable(),
  lastSequence: z.number().int().nonnegative(),
  createdAt: z.iso.datetime({ offset: true }),
  observedAt: z.iso.datetime({ offset: true }),
}).strict();

export const analysisEventPublicSchema = z.object({
  eventId: z.uuid(),
  analysisId: z.uuid(),
  sequence: z.number().int().positive(),
  status: z.enum(["queued", "running", "completed", "failed"]),
  step: z.string().min(1).max(200),
  kind: z.enum(["status", "provisional", "progress", "final"]),
  progressState: z.enum(["started", "completed", "skipped", "degraded"]).nullable(),
  occurredAt: z.iso.datetime({ offset: true }),
}).strict();

const webSocketUrlSchema = z.string().max(2_048).refine((value) => {
  try {
    const url = new URL(value);
    const queryKeys = [...url.searchParams.keys()];
    return (
      (url.protocol === "ws:" || url.protocol === "wss:") &&
      !url.username &&
      !url.password &&
      !url.hash &&
      /^\/api\/v4\/analyses\/[0-9a-f-]{36}\/stream$/u.test(url.pathname) &&
      url.searchParams.getAll("ticket").length === 1 &&
      (url.searchParams.get("ticket")?.length ?? 0) > 0 &&
      queryKeys.every((key) => key === "ticket" || key === "cursor") &&
      url.searchParams.getAll("cursor").length <= 1
    );
  } catch {
    return false;
  }
}, "WebSocket URL must be an absolute ticketed WS(S) URL.");

const captureValue = z
  .string()
  .refine((value) => value.trim().length > 0, "Capture value cannot be blank.")
  .refine(
    (value) => [...value].length <= MAX_CAPTURE_CHARACTERS,
    `Capture value cannot exceed ${MAX_CAPTURE_CHARACTERS} Unicode characters.`,
  );

const selectionCaptureSchema = z.object({
  version: z.literal(1),
  captureId: z.uuid(),
  kind: z.literal("selection"),
  value: captureValue,
  createdAt: z.iso.datetime({ offset: true }),
  source: z.literal("context-menu"),
}).strict();

const linkCaptureSchema = z.object({
  version: z.literal(1),
  captureId: z.uuid(),
  kind: z.literal("link"),
  value: captureValue.refine((value) => {
    try {
      const url = new URL(value);
      return (
        (url.protocol === "http:" || url.protocol === "https:") &&
        url.hostname.length > 0 &&
        url.username.length === 0 &&
        url.password.length === 0 &&
        url.hash.length === 0
      );
    } catch {
      return false;
    }
  }, "Link capture must be an absolute HTTP(S) URL without credentials or a fragment."),
  createdAt: z.iso.datetime({ offset: true }),
  source: z.literal("context-menu"),
}).strict();

export const captureEnvelopeSchema = z.discriminatedUnion("kind", [
  selectionCaptureSchema,
  linkCaptureSchema,
]);

export const internalMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("panel.ready") }).strict(),
  z.object({ type: z.literal("panel.status"), status: z.literal("ready") }).strict(),
  z.object({ type: z.literal("auth.state.get") }).strict(),
  z.object({ type: z.literal("auth.login") }).strict(),
  z.object({ type: z.literal("auth.logout") }).strict(),
  z.object({ type: z.literal("auth.state"), state: authPublicStateSchema }).strict(),
  z.object({ type: z.literal("capture.pending.get") }).strict(),
  z.object({
    type: z.literal("capture.pending"),
    capture: captureEnvelopeSchema.nullable(),
  }).strict(),
  z.object({ type: z.literal("capture.preview"), capture: captureEnvelopeSchema }).strict(),
  z.object({ type: z.literal("capture.pending.clear"), captureId: z.uuid() }).strict(),
  z.object({
    type: z.literal("capture.pending.cleared"),
    captureId: z.uuid(),
    cleared: z.boolean(),
  }).strict(),
  z.object({
    type: z.literal("analysis.create"),
    captureId: z.uuid(),
    consent: z.object({
      external_url_lookup: z.boolean(),
      official_source_lookup: z.boolean(),
    }).strict(),
  }).strict(),
  z.object({ type: z.literal("analysis.active.get") }).strict(),
  z.object({
    type: z.literal("analysis.active"),
    analysis: activeAnalysisPublicSchema.nullable(),
  }).strict(),
  z.object({
    type: z.literal("analysis.submitted"),
    analysis: activeAnalysisPublicSchema,
  }).strict(),
  z.object({
    type: z.literal("analysis.wsTicket.get"),
    analysisId: z.uuid(),
    cursor: z.string().max(128).nullable(),
  }).strict(),
  z.object({
    type: z.literal("analysis.wsTicket.issued"),
    analysisId: z.uuid(),
    url: webSocketUrlSchema,
    expiresAt: z.iso.datetime({ offset: true }),
  }).strict(),
  z.object({
    type: z.literal("analysis.events.get"),
    analysisId: z.uuid(),
    cursor: z.string().max(128).nullable(),
  }).strict(),
  z.object({
    type: z.literal("analysis.events"),
    analysisId: z.uuid(),
    events: z.array(analysisEventPublicSchema).max(100),
    nextCursor: z.string().max(128).nullable(),
  }).strict(),
  z.object({
    type: z.literal("analysis.snapshot.get"),
    analysisId: z.uuid(),
  }).strict(),
  z.object({
    type: z.literal("analysis.snapshot"),
    analysis: z.object({
      analysisId: z.uuid(),
      status: z.enum(["queued", "running", "completed", "failed"]),
      terminal: z.boolean(),
      createdAt: z.iso.datetime({ offset: true }),
    }).strict(),
  }).strict(),
  z.object({
    type: z.literal("analysis.observation.commit"),
    analysisId: z.uuid(),
    cursor: z.string().max(128).nullable(),
    lastSequence: z.number().int().nonnegative(),
    status: z.enum(["queued", "running", "completed", "failed"]),
  }).strict(),
  z.object({
    type: z.literal("analysis.observation"),
    analysis: activeAnalysisPublicSchema.nullable(),
  }).strict(),
  z.object({
    type: z.literal("analysis.transport.error"),
    analysisId: z.uuid(),
    code: submissionErrorCodeSchema,
    retryable: z.boolean(),
  }).strict(),
  z.object({
    type: z.literal("analysis.error"),
    code: submissionErrorCodeSchema,
    retryable: z.boolean(),
  }).strict(),
]);

export type CaptureEnvelope = z.infer<typeof captureEnvelopeSchema>;
export type ActiveAnalysisPublic = z.infer<typeof activeAnalysisPublicSchema>;
export type AnalysisEventPublic = z.infer<typeof analysisEventPublicSchema>;
export type InternalMessage = z.infer<typeof internalMessageSchema>;
