import type { AnalysisApi } from "./analysis-api.types";

import { HttpAnalysisApi } from "./http-analysis-api";
import { MockAnalysisApi } from "./mock-analysis-api";
import { getStoredAccessToken } from "@/lib/auth/oidc";

let client: AnalysisApi | undefined;

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

export function getAnalysisApi(): AnalysisApi {
  if (client) return client;

  // Production API is the default. The in-memory adapter is opt-in for
  // isolated component development only.
  const useMockApi = process.env.NEXT_PUBLIC_USE_MOCK_API === "true";
  client = useMockApi ? new MockAnalysisApi() : new HttpAnalysisApi(undefined, getAccessToken);
  return client;
}
