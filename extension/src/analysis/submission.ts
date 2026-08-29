import { AuthFlowError } from "../auth/oidc";
import type { PendingCaptureStore } from "../capture/pending-store";
import {
  TrustGuardApiError,
  type SecurityConsent,
  type SecurityTriageCreateRequest,
  type SubmissionErrorCode,
  type TrustGuardAnalysisApi,
} from "../api/client";
import type { CaptureEnvelope } from "../contracts/internal";
import { fingerprintAnalysisRequest } from "./session-store";
import type {
  ActiveAnalysisState,
  ActiveAnalysisStore,
  SubmissionAttemptStore,
} from "./session-store";

export interface AccessTokenProvider {
  getValidAccessToken(): Promise<string>;
}

export interface AnalysisSubmissionDependencies {
  api: TrustGuardAnalysisApi | null;
  auth: AccessTokenProvider;
  pendingCaptures: PendingCaptureStore;
  activeAnalyses: ActiveAnalysisStore;
  attempts: SubmissionAttemptStore;
}

function submissionError(error: unknown): TrustGuardApiError {
  if (error instanceof TrustGuardApiError) return error;
  if (error instanceof AuthFlowError) {
    const code: SubmissionErrorCode = error.code === "not_configured" ? "not_configured" : "reauth_required";
    return new TrustGuardApiError(code, false, 0);
  }
  return new TrustGuardApiError("storage_error", true, 0);
}

export function createAnalysisRequest(
  capture: CaptureEnvelope,
  consent: SecurityConsent,
  executionMode: "inline" | "async",
): SecurityTriageCreateRequest {
  return {
    message: capture.value,
    consent: {
      external_url_lookup: consent.external_url_lookup,
      official_source_lookup: consent.official_source_lookup,
    },
    execution_mode: executionMode,
  };
}

export class AnalysisSubmissionService {
  private readonly inFlight = new Map<string, Promise<ActiveAnalysisState>>();

  constructor(private readonly dependencies: AnalysisSubmissionDependencies) {}

  submit(captureId: string, consent: SecurityConsent): Promise<ActiveAnalysisState> {
    const current = this.inFlight.get(captureId);
    if (current !== undefined) return current;
    const submission = this.submitOnce(captureId, consent).finally(() => {
      if (this.inFlight.get(captureId) === submission) this.inFlight.delete(captureId);
    });
    this.inFlight.set(captureId, submission);
    return submission;
  }

  private async submitOnce(captureId: string, consent: SecurityConsent): Promise<ActiveAnalysisState> {
    let executionMode: "inline" | "async" = "inline";
    try {
      if (this.dependencies.api === null) {
        throw new TrustGuardApiError("not_configured", false, 0);
      }
      const capture = await this.dependencies.pendingCaptures.read();
      if (capture?.captureId !== captureId) {
        throw new TrustGuardApiError("stale_capture", false, 0);
      }

      let useAsync = false;
      try {
        useAsync = (await this.dependencies.api.getCapabilities()).securityAsyncExecution;
      } catch {
        // Capability discovery is fail-soft; the compatible inline path remains available.
      }
      executionMode = useAsync ? "async" : "inline";
      const request = createAnalysisRequest(capture, consent, executionMode);
      const fingerprint = await fingerprintAnalysisRequest(request);
      const attempt = await this.dependencies.attempts.resolve(capture.captureId, fingerprint);
      const accessToken = await this.dependencies.auth.getValidAccessToken();
      const result = await this.dependencies.api.createAnalysis(request, accessToken, attempt.idempotencyKey);

      const state = await this.dependencies.activeAnalyses.save(result);
      await this.dependencies.pendingCaptures.clearIfMatching(capture.captureId);
      await this.dependencies.attempts.clearIfMatching(capture.captureId);
      return state;
    } catch (error: unknown) {
      const failure = submissionError(error);
      if (
        executionMode === "inline" &&
        (failure.code === "timeout" || failure.code === "offline")
      ) {
        throw new TrustGuardApiError(failure.code, false, failure.status);
      }
      throw failure;
    }
  }
}
