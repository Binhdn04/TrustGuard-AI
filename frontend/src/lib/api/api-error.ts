import { userFacingErrorMessage } from "./user-facing-error";

export class ApiError extends Error {
  constructor(
    _unsafeMessage: string,
    readonly code: string,
    readonly retryable: boolean,
    readonly status: number,
    readonly details: Record<string, unknown> = {},
  ) {
    // Callers may construct this from an API, provider, or browser error. The
    // original text must never become UI content.
    super(userFacingErrorMessage(code, retryable));
    this.name = "ApiError";
  }
}
