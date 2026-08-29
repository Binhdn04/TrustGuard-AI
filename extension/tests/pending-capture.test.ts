import { describe, expect, it } from "vitest";

import {
  PENDING_CAPTURE_STORAGE_KEY,
  PendingCaptureStore,
  SerialTaskQueue,
} from "../src/capture/pending-store";
import { captureEnvelopeSchema, type CaptureEnvelope } from "../src/contracts/internal";

class FakeSessionStorage {
  readonly values: Record<string, unknown> = {};

  get(key: string): Promise<Record<string, unknown>> {
    return Promise.resolve({ [key]: this.values[key] });
  }

  set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, items);
    return Promise.resolve();
  }

  remove(key: string): Promise<void> {
    delete this.values[key];
    return Promise.resolve();
  }
}

function capture(captureId: string, value: string): CaptureEnvelope {
  return captureEnvelopeSchema.parse({
    version: 1,
    captureId,
    kind: "selection",
    value,
    createdAt: "2026-08-29T10:00:00.000Z",
    source: "context-menu",
  });
}

const firstCapture = capture("4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e", "first");
const secondCapture = capture("0e8bfbc6-ec37-4919-aea7-11fd6e90d334", "second");

describe("pending capture session storage", () => {
  it("expires and deletes the pending capture at its TTL", async () => {
    const storage = new FakeSessionStorage();
    const store = new PendingCaptureStore(storage, 1_000);
    await store.save(firstCapture, 10_000);

    await expect(store.read(10_999)).resolves.toEqual(firstCapture);
    await expect(store.read(11_000)).resolves.toBeNull();
    expect(storage.values).not.toHaveProperty(PENDING_CAPTURE_STORAGE_KEY);
  });

  it("removes malformed session data instead of exposing it", async () => {
    const storage = new FakeSessionStorage();
    storage.values[PENDING_CAPTURE_STORAGE_KEY] = {
      version: 1,
      capture: { pageHtml: "<script>unsafe</script>" },
      expiresAt: 99_999,
    };

    await expect(new PendingCaptureStore(storage).read(10_000)).resolves.toBeNull();
    expect(storage.values).not.toHaveProperty(PENDING_CAPTURE_STORAGE_KEY);
  });

  it("does not let a stale cancel delete a newer capture", async () => {
    const storage = new FakeSessionStorage();
    const store = new PendingCaptureStore(storage);
    await store.save(secondCapture, 10_000);

    await expect(store.clearIfMatching(firstCapture.captureId, 10_001)).resolves.toBe(false);
    await expect(store.read(10_001)).resolves.toEqual(secondCapture);
  });

  it("serializes rapid captures so the last user gesture wins", async () => {
    const storage = new FakeSessionStorage();
    const store = new PendingCaptureStore(storage);
    const queue = new SerialTaskQueue();
    let releaseFirst = (): void => undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const order: string[] = [];

    const first = queue.run(async () => {
      order.push("first:start");
      await firstGate;
      await store.save(firstCapture, 10_000);
      order.push("first:end");
    });
    const second = queue.run(async () => {
      order.push("second:start");
      await store.save(secondCapture, 10_001);
      order.push("second:end");
    });

    await Promise.resolve();
    expect(order).toEqual(["first:start"]);
    releaseFirst();
    await Promise.all([first, second]);
    expect(order).toEqual(["first:start", "first:end", "second:start", "second:end"]);
    await expect(store.read(10_002)).resolves.toEqual(secondCapture);
  });
});
