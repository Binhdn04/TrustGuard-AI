import { z } from "zod";

import { captureEnvelopeSchema, type CaptureEnvelope } from "../contracts/internal";

export const PENDING_CAPTURE_STORAGE_KEY = "trustguard.pendingCapture.v1";
export const PENDING_CAPTURE_TTL_MS = 5 * 60 * 1_000;

const pendingCaptureRecordSchema = z.object({
  version: z.literal(1),
  capture: captureEnvelopeSchema,
  expiresAt: z.number().int().positive(),
}).strict();

interface SessionStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export class PendingCaptureStore {
  constructor(
    private readonly storage: SessionStorageArea,
    private readonly ttlMs = PENDING_CAPTURE_TTL_MS,
  ) {}

  async save(capture: CaptureEnvelope, now = Date.now()): Promise<void> {
    await this.storage.set({
      [PENDING_CAPTURE_STORAGE_KEY]: {
        version: 1,
        capture,
        expiresAt: now + this.ttlMs,
      },
    });
  }

  async read(now = Date.now()): Promise<CaptureEnvelope | null> {
    const stored = await this.storage.get(PENDING_CAPTURE_STORAGE_KEY);
    const parsed = pendingCaptureRecordSchema.safeParse(stored[PENDING_CAPTURE_STORAGE_KEY]);
    if (!parsed.success || parsed.data.expiresAt <= now) {
      if (stored[PENDING_CAPTURE_STORAGE_KEY] !== undefined) {
        await this.storage.remove(PENDING_CAPTURE_STORAGE_KEY);
      }
      return null;
    }
    return parsed.data.capture;
  }

  async clear(): Promise<void> {
    await this.storage.remove(PENDING_CAPTURE_STORAGE_KEY);
  }

  async clearIfMatching(captureId: string, now = Date.now()): Promise<boolean> {
    const capture = await this.read(now);
    if (capture?.captureId !== captureId) {
      return false;
    }
    await this.clear();
    return true;
  }
}

export class SerialTaskQueue {
  private tail: Promise<void> = Promise.resolve();

  run<T>(task: () => Promise<T>): Promise<T> {
    const result = this.tail.then(task, task);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
