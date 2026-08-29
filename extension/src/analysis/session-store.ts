import { z } from "zod";

import type { AnalysisSubmissionResult, SecurityTriageCreateRequest } from "../api/client";

export const ACTIVE_ANALYSIS_STORAGE_KEY = "trustguard.activeAnalysis.v1";
export const SUBMISSION_ATTEMPT_STORAGE_KEY = "trustguard.submissionAttempt.v1";

const activeAnalysisSchema = z.object({
  version: z.literal(1),
  analysisId: z.uuid(),
  executionMode: z.enum(["inline", "async"]),
  status: z.enum(["queued", "running", "completed", "failed"]),
  cursor: z.string().max(128).nullable(),
  lastSequence: z.number().int().nonnegative().default(0),
  createdAt: z.iso.datetime({ offset: true }),
  observedAt: z.iso.datetime({ offset: true }),
}).strict();

const submissionAttemptSchema = z.object({
  version: z.literal(1),
  captureId: z.uuid(),
  requestFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  idempotencyKey: z.uuid(),
}).strict();

export type ActiveAnalysisState = z.infer<typeof activeAnalysisSchema>;
export type SubmissionAttempt = z.infer<typeof submissionAttemptSchema>;

export interface AnalysisSessionStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export async function fingerprintAnalysisRequest(request: SecurityTriageCreateRequest): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(request));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

export class ActiveAnalysisStore {
  constructor(private readonly storage: AnalysisSessionStorageArea) {}

  async save(result: AnalysisSubmissionResult, observedAt = new Date().toISOString()): Promise<ActiveAnalysisState> {
    const state = activeAnalysisSchema.parse({
      version: 1,
      analysisId: result.analysisId,
      executionMode: result.executionMode,
      status: result.status,
      cursor: null,
      lastSequence: 0,
      createdAt: result.createdAt,
      observedAt,
    });
    await this.storage.set({ [ACTIVE_ANALYSIS_STORAGE_KEY]: state });
    return state;
  }

  async read(): Promise<ActiveAnalysisState | null> {
    const value = (await this.storage.get(ACTIVE_ANALYSIS_STORAGE_KEY))[ACTIVE_ANALYSIS_STORAGE_KEY];
    const parsed = activeAnalysisSchema.safeParse(value);
    if (!parsed.success && value !== undefined) await this.storage.remove(ACTIVE_ANALYSIS_STORAGE_KEY);
    return parsed.success ? parsed.data : null;
  }

  async observe(
    analysisId: string,
    observation: {
      cursor: string | null;
      lastSequence: number;
      status: ActiveAnalysisState["status"];
      observedAt?: string;
    },
  ): Promise<ActiveAnalysisState | null> {
    const current = await this.read();
    if (current === null || current.analysisId !== analysisId || observation.lastSequence < current.lastSequence) {
      return current;
    }
    const currentTerminal = current.status === "completed" || current.status === "failed";
    const nextTerminal = observation.status === "completed" || observation.status === "failed";
    const status = currentTerminal && !nextTerminal ? current.status : observation.status;
    const next = activeAnalysisSchema.parse({
      ...current,
      cursor: observation.cursor ?? current.cursor,
      lastSequence: observation.lastSequence,
      status,
      observedAt: observation.observedAt ?? new Date().toISOString(),
    });
    await this.storage.set({ [ACTIVE_ANALYSIS_STORAGE_KEY]: next });
    return next;
  }
}

export class SubmissionAttemptStore {
  constructor(
    private readonly storage: AnalysisSessionStorageArea,
    private readonly randomUUID: () => string = () => crypto.randomUUID(),
  ) {}

  async resolve(captureId: string, requestFingerprint: string): Promise<SubmissionAttempt> {
    const value = (await this.storage.get(SUBMISSION_ATTEMPT_STORAGE_KEY))[SUBMISSION_ATTEMPT_STORAGE_KEY];
    const parsed = submissionAttemptSchema.safeParse(value);
    if (!parsed.success && value !== undefined) await this.storage.remove(SUBMISSION_ATTEMPT_STORAGE_KEY);
    if (
      parsed.success &&
      parsed.data.captureId === captureId &&
      parsed.data.requestFingerprint === requestFingerprint
    ) {
      return parsed.data;
    }
    const attempt = submissionAttemptSchema.parse({
      version: 1,
      captureId,
      requestFingerprint,
      idempotencyKey: parsed.success && parsed.data.captureId === captureId ? this.randomUUID() : captureId,
    });
    await this.storage.set({ [SUBMISSION_ATTEMPT_STORAGE_KEY]: attempt });
    return attempt;
  }

  async clearIfMatching(captureId: string): Promise<void> {
    const value = (await this.storage.get(SUBMISSION_ATTEMPT_STORAGE_KEY))[SUBMISSION_ATTEMPT_STORAGE_KEY];
    const parsed = submissionAttemptSchema.safeParse(value);
    if (!parsed.success) {
      if (value !== undefined) await this.storage.remove(SUBMISSION_ATTEMPT_STORAGE_KEY);
      return;
    }
    if (parsed.data.captureId === captureId) await this.storage.remove(SUBMISSION_ATTEMPT_STORAGE_KEY);
  }
}
