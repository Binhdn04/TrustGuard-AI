import { ApiError } from "./api-error";
import { userFacingErrorMessage } from "./user-facing-error";

function configuredApiUrl(explicitUrl?: string): string | undefined {
  const value = explicitUrl ?? process.env.NEXT_PUBLIC_API_URL;
  return value?.trim() || undefined;
}

export function resolveSecurityApiUrl(explicitUrl?: string): string {
  const configuredUrl = configuredApiUrl(explicitUrl);
  if (!configuredUrl) {
    throw new ApiError(
      userFacingErrorMessage("API_CONFIGURATION_ERROR"),
      "API_CONFIGURATION_ERROR",
      false,
      0,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(configuredUrl);
  } catch {
    throw new ApiError(
      userFacingErrorMessage("API_CONFIGURATION_ERROR"),
      "API_CONFIGURATION_ERROR",
      false,
      0,
    );
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ApiError(
      userFacingErrorMessage("API_CONFIGURATION_ERROR"),
      "API_CONFIGURATION_ERROR",
      false,
      0,
    );
  }
  return configuredUrl.replace(/\/$/, "");
}

export function networkError(apiUrl: string): ApiError {
  void apiUrl;
  return new ApiError(
    userFacingErrorMessage("NETWORK_ERROR", true),
    "NETWORK_ERROR",
    true,
    0,
  );
}
