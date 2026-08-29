import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  TrustGuardApiError,
  type AnalysisSubmissionResult,
  type SecurityTriageCreateRequest,
  type TrustGuardAnalysisApi,
} from "../src/api/client";
import {
  ACTIVE_ANALYSIS_STORAGE_KEY,
  SUBMISSION_ATTEMPT_STORAGE_KEY,
  ActiveAnalysisStore,
  SubmissionAttemptStore,
} from "../src/analysis/session-store";
import { AnalysisSubmissionService, createAnalysisRequest } from "../src/analysis/submission";
import { PendingCaptureStore } from "../src/capture/pending-store";
import { captureEnvelopeSchema, type CaptureEnvelope } from "../src/contracts/internal";

class MemoryStorage {
  readonly values: Record<string, unknown> = {};

  get(key: string): Promise<Record<string, unknown>> {
    return Promise.resolve({ [key]: this.values[key] });
  }

  set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.values, items);
    return Promise.resolve();
  }

  remove(key: string | string[]): Promise<void> {
    for (const item of typeof key === "string" ? [key] : key) delete this.values[item];
    return Promise.resolve();
  }
}

const captureId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";
const changedKey = "0e8bfbc6-ec37-4919-aea7-11fd6e90d334";
const result: AnalysisSubmissionResult = {
  analysisId: "3b4629b5-6ea1-4e9f-9acc-f1918fe07ae0",
  executionMode: "async",
  status: "queued",
  createdAt: "2026-08-29T10:00:01.000Z",
};
const capture: CaptureEnvelope = captureEnvelopeSchema.parse({
  version: 1,
  captureId,
  kind: "selection",
  value: "Ngân hàng yêu cầu cung cấp OTP",
  createdAt: "2026-08-29T10:00:00.000Z",
  source: "context-menu",
});
const consent = { external_url_lookup: false, official_source_lookup: true };

function setup(api: TrustGuardAnalysisApi, randomUUID = () => changedKey) {
  const storage = new MemoryStorage();
  const pendingCaptures = new PendingCaptureStore(storage);
  const activeAnalyses = new ActiveAnalysisStore(storage);
  const attempts = new SubmissionAttemptStore(storage, randomUUID);
  const auth = { getValidAccessToken: vi.fn().mockResolvedValue("private-access-token") };
  const submissions = new AnalysisSubmissionService({ api, auth, pendingCaptures, activeAnalyses, attempts });
  return { storage, pendingCaptures, activeAnalyses, attempts, auth, submissions };
}

describe("Phase 5 analysis submission", () => {
  it("maps capture directly, chooses async, clears raw capture and stores minimal state", async () => {
    const createAnalysis = vi.fn().mockResolvedValue(result);
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn().mockResolvedValue({ securityAsyncExecution: true }),
      createAnalysis,
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    await expect(context.submissions.submit(captureId, consent)).resolves.toMatchObject({
      analysisId: result.analysisId,
      executionMode: result.executionMode,
      status: result.status,
      cursor: null,
    });

    expect(createAnalysis).toHaveBeenCalledWith({
      message: capture.value,
      consent,
      execution_mode: "async",
    }, "private-access-token", captureId);
    await expect(context.pendingCaptures.read()).resolves.toBeNull();
    expect(context.storage.values).not.toHaveProperty(SUBMISSION_ATTEMPT_STORAGE_KEY);
    expect(JSON.stringify(context.storage.values)).not.toContain(capture.value);
    expect(JSON.stringify(context.storage.values)).not.toContain("private-access-token");
    expect(context.storage.values[ACTIVE_ANALYSIS_STORAGE_KEY]).toEqual(expect.objectContaining({
      analysisId: result.analysisId,
      executionMode: "async",
      status: "queued",
      cursor: null,
      lastSequence: 0,
    }));
  });

  it("persists cursor observations monotonically and never regresses a terminal status", async () => {
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn(),
      createAnalysis: vi.fn(),
    };
    const context = setup(api);
    await context.activeAnalyses.save(result);

    await context.activeAnalyses.observe(result.analysisId, {
      cursor: "Mg",
      lastSequence: 2,
      status: "completed",
    });
    await context.activeAnalyses.observe(result.analysisId, {
      cursor: "MQ",
      lastSequence: 1,
      status: "running",
    });

    await expect(context.activeAnalyses.read()).resolves.toMatchObject({
      cursor: "Mg",
      lastSequence: 2,
      status: "completed",
    });
  });

  it("falls back to inline when capability discovery fails", async () => {
    const inline = { ...result, executionMode: "inline" as const, status: "completed" as const };
    const createAnalysis = vi.fn().mockResolvedValue(inline);
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn().mockRejectedValue(new Error("capability unavailable")),
      createAnalysis,
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    await expect(context.submissions.submit(captureId, consent)).resolves.toMatchObject({
      analysisId: inline.analysisId,
      executionMode: inline.executionMode,
      status: inline.status,
      cursor: null,
    });
    expect(createAnalysis).toHaveBeenCalledWith(
      expect.objectContaining({ execution_mode: "inline" }),
      "private-access-token",
      captureId,
    );
  });

  it("deduplicates concurrent clicks in the background", async () => {
    let resolveRequest!: (resolved: AnalysisSubmissionResult) => void;
    const gate = new Promise<AnalysisSubmissionResult>((resolve) => {
      resolveRequest = resolve;
    });
    const createAnalysis = vi.fn().mockReturnValue(gate);
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn().mockResolvedValue({ securityAsyncExecution: true }),
      createAnalysis,
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    const first = context.submissions.submit(captureId, consent);
    const second = context.submissions.submit(captureId, consent);
    expect(first).toBe(second);
    resolveRequest(result);
    await Promise.all([first, second]);
    expect(createAnalysis).toHaveBeenCalledTimes(1);
  });

  it("reuses the same key for an async network retry and rotates it when consent changes", async () => {
    const keys: string[] = [];
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn().mockResolvedValue({ securityAsyncExecution: true }),
      createAnalysis: vi.fn().mockImplementation(
        (_request: SecurityTriageCreateRequest, _token: string, key: string) => {
          keys.push(key);
          return Promise.reject(new TrustGuardApiError("offline", true, 0));
        },
      ),
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    await expect(context.submissions.submit(captureId, consent)).rejects.toMatchObject({ retryable: true });
    await expect(context.submissions.submit(captureId, consent)).rejects.toMatchObject({ retryable: true });
    await expect(context.submissions.submit(captureId, {
      ...consent,
      external_url_lookup: true,
    })).rejects.toMatchObject({ retryable: true });

    expect(keys).toEqual([captureId, captureId, changedKey]);
    await expect(context.pendingCaptures.read()).resolves.toEqual(capture);
  });

  it("marks ambiguous inline network failure as unsafe to retry", async () => {
    const api: TrustGuardAnalysisApi = {
      getCapabilities: vi.fn().mockResolvedValue({ securityAsyncExecution: false }),
      createAnalysis: vi.fn().mockRejectedValue(new TrustGuardApiError("timeout", true, 0)),
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    await expect(context.submissions.submit(captureId, consent)).rejects.toMatchObject({
      code: "timeout",
      retryable: false,
    });
    await expect(context.pendingCaptures.read()).resolves.toEqual(capture);
  });

  it("rejects a stale ID before auth or API calls", async () => {
    const getCapabilities = vi.fn();
    const api: TrustGuardAnalysisApi = {
      getCapabilities,
      createAnalysis: vi.fn(),
    };
    const context = setup(api);
    await context.pendingCaptures.save(capture);

    await expect(context.submissions.submit(changedKey, consent)).rejects.toMatchObject({ code: "stale_capture" });
    expect(context.auth.getValidAccessToken).not.toHaveBeenCalled();
    expect(getCapabilities).not.toHaveBeenCalled();
  });

  it("matches the shared Phase 0 capture/consent fixture without adding metadata", () => {
    const fixture = JSON.parse(readFileSync(
      new URL("../../tests/fixtures/chrome_extension/phase0_cases.json", import.meta.url),
      "utf8",
    )) as {
      cases: Array<{
        capture: { kind: "selection" | "link"; value: string };
        consent: typeof consent;
      }>;
    };

    for (const [index, item] of fixture.cases.entries()) {
      const envelope = captureEnvelopeSchema.parse({
        version: 1,
        captureId: index === 0 ? captureId : crypto.randomUUID(),
        kind: item.capture.kind,
        value: item.capture.value,
        createdAt: "2026-08-29T10:00:00.000Z",
        source: "context-menu",
      });
      expect(createAnalysisRequest(envelope, item.consent, "inline")).toEqual({
        message: item.capture.value,
        consent: item.consent,
        execution_mode: "inline",
      });
    }
  });
});
