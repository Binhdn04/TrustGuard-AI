import { z } from "zod";

export const authErrorCodeSchema = z.enum([
  "not_configured",
  "canceled",
  "redirect_mismatch",
  "state_mismatch",
  "expired",
  "invalid_token",
  "network",
  "reauth_required",
]);

export const authPublicStateSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("not_configured") }).strict(),
  z.object({ status: z.literal("signed_out") }).strict(),
  z.object({ status: z.literal("authenticating") }).strict(),
  z.object({ status: z.literal("signed_in") }).strict(),
  z.object({ status: z.literal("error"), code: authErrorCodeSchema }).strict(),
]);

export type AuthErrorCode = z.infer<typeof authErrorCodeSchema>;
export type AuthPublicState = z.infer<typeof authPublicStateSchema>;
