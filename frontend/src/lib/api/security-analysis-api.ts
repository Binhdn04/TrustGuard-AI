import { HttpSecurityAnalysisApi } from "./http-security-analysis-api";
import type { SecurityAnalysisApi } from "./security-analysis-api.types";
import { getStoredAccessToken } from "@/lib/auth/oidc";

let client: SecurityAnalysisApi | undefined;

function getAccessToken(): string | null | undefined {
  if (typeof window === "undefined") return undefined;
  const accessToken = getStoredAccessToken();
  if (accessToken) return accessToken;
  let role = "user";
  try {
    const stored = window.localStorage.getItem("ai_protect_user");
    role = stored ? (JSON.parse(stored) as { role?: string }).role ?? "user" : "user";
  } catch {
    window.localStorage.removeItem("ai_protect_user");
  }
  return role === "security_admin"
    ? process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN
    : process.env.NEXT_PUBLIC_DEMO_USER_TOKEN;
}

export function getSecurityAnalysisApi(): SecurityAnalysisApi {
  client ??= new HttpSecurityAnalysisApi(undefined, getAccessToken);
  return client;
}
