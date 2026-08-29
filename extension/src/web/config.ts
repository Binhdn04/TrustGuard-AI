import { z } from "zod";

import { parseExactApiOrigin } from "../api/config";

export interface TrustGuardWebConfig {
  baseUrl: string;
}

export type WebEnvironment = Record<string, string | undefined>;

export function resolveWebConfig(environment: WebEnvironment): TrustGuardWebConfig | null {
  const value = environment.VITE_TRUSTGUARD_WEB_URL?.trim();
  return value ? { baseUrl: parseExactApiOrigin(value) } : null;
}

export function getBundledWebConfig(): TrustGuardWebConfig | null {
  return resolveWebConfig(import.meta.env);
}

export function buildCaseUrl(config: TrustGuardWebConfig, analysisId: string): string {
  const validatedId = z.uuid().parse(analysisId);
  const url = new URL(`/cases/${validatedId}`, config.baseUrl);
  if (url.origin !== config.baseUrl) throw new Error("Case URL escaped the configured TrustGuard web origin.");
  return url.toString();
}
