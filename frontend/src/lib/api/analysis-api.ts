import type { AnalysisApi } from "./analysis-api.types";

import { HttpAnalysisApi } from "./http-analysis-api";
import { MockAnalysisApi } from "./mock-analysis-api";

let client: AnalysisApi | undefined;

export function getAnalysisApi(): AnalysisApi {
  if (client) return client;

  // Production API is the default. The in-memory adapter is opt-in for
  // isolated component development only.
  const useMockApi = process.env.NEXT_PUBLIC_USE_MOCK_API === "true";
  client = useMockApi ? new MockAnalysisApi() : new HttpAnalysisApi();
  return client;
}
