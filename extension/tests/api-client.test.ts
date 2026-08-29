import { describe, expect, it, vi } from "vitest";

import { HttpTrustGuardAnalysisApi, TrustGuardApiError } from "../src/api/client";

const analysisId = "4d5c2bc5-20ab-4ec4-8c7a-2c307d24c64e";
const conversationId = "0e8bfbc6-ec37-4919-aea7-11fd6e90d334";
const otherAnalysisId = "3b4629b5-6ea1-4e9f-9acc-f1918fe07ae0";
const createdAt = "2026-08-29T10:00:00.000Z";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("TrustGuard v4 HTTP client", () => {
  it("discovers async capability without sending credentials", async () => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({ security_async_execution: true }));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "http://localhost:8000" },
      { fetcher },
    );

    await expect(api.getCapabilities()).resolves.toEqual({ securityAsyncExecution: true });
    expect(fetcher).toHaveBeenCalledWith(
      "http://localhost:8000/api/v4/capabilities",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        headers: { Accept: "application/json" },
      }),
    );
  });

  it("submits exact v4 body and keeps bearer/idempotency in background request headers", async () => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({
      contract_version: "v4",
      analysis_id: analysisId,
      conversation_id: conversationId,
      conversation_version: 1,
      status: "completed",
      scope_decision: "IN_SCOPE",
      terminal: true,
      created_at: createdAt,
    }));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "http://localhost:8000" },
      { fetcher },
    );
    const request = {
      message: "Ngân hàng yêu cầu cung cấp OTP",
      consent: { external_url_lookup: false, official_source_lookup: true },
      execution_mode: "inline" as const,
    };

    await expect(api.createAnalysis(request, "private-access-token", analysisId)).resolves.toEqual({
      analysisId,
      executionMode: "inline",
      status: "completed",
      createdAt,
    });
    const [, init] = fetcher.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual(request);
    expect(init.headers).toEqual(expect.objectContaining({
      Authorization: "Bearer private-access-token",
      "Idempotency-Key": analysisId,
    }));
  });

  it("accepts the async acknowledgement contract", async () => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({
      contract_version: "v4",
      analysis_id: analysisId,
      conversation_id: conversationId,
      conversation_version: 1,
      status: "queued",
      created_at: createdAt,
    }, 202));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "https://api.example" },
      { fetcher },
    );

    await expect(api.createAnalysis({
      message: "https://example.test/login",
      consent: { external_url_lookup: true, official_source_lookup: false },
      execution_mode: "async",
    }, "private-access-token", analysisId)).resolves.toMatchObject({
      analysisId,
      executionMode: "async",
      status: "queued",
    });
  });

  it("issues tickets, polls minimized events and fetches an authoritative snapshot", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        contract_version: "v4",
        ticket: "single-use-ticket",
        analysis_id: analysisId,
        expires_at: createdAt,
        stream_path: `/api/v4/analyses/${analysisId}/stream`,
        single_use: true,
      }, 201))
      .mockResolvedValueOnce(jsonResponse({
        contract_version: "v4",
        events: [{
          event_id: conversationId,
          analysis_id: analysisId,
          sequence: 2,
          status: "running",
          step: "understanding",
          kind: "progress",
          progress_state: "started",
          occurred_at: createdAt,
          message: "must be stripped",
          evidence_refs: ["must-be-stripped"],
          risk_hint: "HIGH_RISK",
        }, {
          event_id: analysisId,
          analysis_id: otherAnalysisId,
          sequence: 99,
          status: "completed",
          step: "assistant_response",
          kind: "final",
          progress_state: null,
          occurred_at: createdAt,
        }],
        next_cursor: "Mg",
      }))
      .mockResolvedValueOnce(jsonResponse({
        contract_version: "v4",
        analysis_id: analysisId,
        status: "completed",
        terminal: true,
        created_at: createdAt,
        explanation: "Phase 7 only",
      }));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "https://api.example" },
      { fetcher },
    );

    await expect(api.createWebSocketTicket(analysisId, "private-token")).resolves.toMatchObject({
      ticket: "single-use-ticket",
      analysisId,
    });
    await expect(api.getAnalysisEvents(analysisId, "MQ", "private-token")).resolves.toEqual({
      events: [{
        eventId: conversationId,
        analysisId,
        sequence: 2,
        status: "running",
        step: "understanding",
        kind: "progress",
        progressState: "started",
        occurredAt: createdAt,
      }],
      nextCursor: "Mg",
    });
    await expect(api.getAnalysis(analysisId, "private-token")).resolves.toEqual({
      analysisId,
      status: "completed",
      terminal: true,
      createdAt,
    });

    expect(fetcher.mock.calls.map((call) => (call as [string, RequestInit])[0])).toEqual([
      "https://api.example/api/v4/ws-tickets",
      `https://api.example/api/v4/analyses/${analysisId}/events?limit=100&cursor=MQ`,
      `https://api.example/api/v4/analyses/${analysisId}`,
    ]);
    for (const [, init] of fetcher.mock.calls as Array<[string, RequestInit]>) {
      expect(init.headers).toEqual(expect.objectContaining({ Authorization: "Bearer private-token" }));
    }
  });

  it.each([
    [401, "reauth_required", false],
    [403, "forbidden", false],
    [409, "conflict", false],
    [422, "validation", false],
    [429, "rate_limited", true],
    [500, "server_error", true],
  ] as const)("maps HTTP %s to %s", async (status, code, retryable) => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({
      error: { code: "SERVER_CODE", message: "must not reach panel", retryable },
    }, status));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "https://api.example" },
      { fetcher },
    );

    const failure = await api.getCapabilities().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(TrustGuardApiError);
    expect(failure).toMatchObject({ code, retryable, status });
    expect(String(failure)).not.toContain("must not reach panel");
  });

  it("maps aborts and network failures without leaking request data", async () => {
    const fetcher = vi.fn().mockImplementation((_input, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(new Error("private request failed")));
    }));
    const api = new HttpTrustGuardAnalysisApi(
      { baseUrl: "https://api.example" },
      { fetcher, timeoutMs: 1 },
    );

    await expect(api.getCapabilities()).rejects.toMatchObject({ code: "timeout", retryable: true });

    const offline = new HttpTrustGuardAnalysisApi(
      { baseUrl: "https://api.example" },
      { fetcher: vi.fn().mockRejectedValue(new Error("private network detail")) },
    );
    await expect(offline.getCapabilities()).rejects.toMatchObject({ code: "offline", retryable: true });
  });
});
