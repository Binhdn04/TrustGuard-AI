import { z } from "zod";

import { authPublicStateSchema } from "../auth/public-state";

export const MAX_CAPTURE_CHARACTERS = 5_000;

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
]);

export type CaptureEnvelope = z.infer<typeof captureEnvelopeSchema>;
export type InternalMessage = z.infer<typeof internalMessageSchema>;
