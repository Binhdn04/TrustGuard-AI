import { ApiError } from "./api-error";

function configuredApiUrl(explicitUrl?: string): string | undefined {
  const value = explicitUrl ?? process.env.NEXT_PUBLIC_API_URL;
  return value?.trim() || undefined;
}

export function resolveSecurityApiUrl(explicitUrl?: string): string {
  const configuredUrl = configuredApiUrl(explicitUrl);
  if (!configuredUrl) {
    throw new ApiError(
      "Thiếu NEXT_PUBLIC_API_URL. Hãy cấu hình URL public của service backend rồi build lại frontend.",
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
      "NEXT_PUBLIC_API_URL phải là một URL HTTP(S) hợp lệ.",
      "API_CONFIGURATION_ERROR",
      false,
      0,
    );
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ApiError(
      "NEXT_PUBLIC_API_URL phải dùng giao thức HTTP hoặc HTTPS.",
      "API_CONFIGURATION_ERROR",
      false,
      0,
    );
  }
  return configuredUrl.replace(/\/$/, "");
}

export function networkError(apiUrl: string): ApiError {
  return new ApiError(
    `Không thể kết nối tới API tại ${apiUrl}. Kiểm tra NEXT_PUBLIC_API_URL, CORS_ORIGINS và trạng thái backend trên Railway.`,
    "NETWORK_ERROR",
    true,
    0,
  );
}
