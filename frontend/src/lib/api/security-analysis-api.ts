import { HttpSecurityAnalysisApi } from "./http-security-analysis-api";
import type { SecurityAnalysisApi } from "./security-analysis-api.types";

let client: SecurityAnalysisApi | undefined;

function getAccessToken(): string | null | undefined {
  if (typeof window === "undefined") return undefined;
  return window.localStorage.getItem("ai_protect_access_token")
    ?? (window.localStorage.getItem("ai_protect_user")?.includes("security_admin")
      ? process.env.NEXT_PUBLIC_DEMO_ADMIN_TOKEN
      : process.env.NEXT_PUBLIC_DEMO_USER_TOKEN);
}

export function getSecurityAnalysisApi(): SecurityAnalysisApi {
  client ??= new HttpSecurityAnalysisApi(undefined, getAccessToken);
  return client;
}
