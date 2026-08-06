import type { AnalysisApi } from "@/types/analysis";

import { HttpAnalysisApi } from "./http-analysis-api";
import { MockAnalysisApi } from "./mock-analysis-api";

let client: AnalysisApi | undefined;

export function getAnalysisApi(): AnalysisApi {
  if (client) return client;

  const useMockApi = process.env.NEXT_PUBLIC_USE_MOCK_API === "true";
  client = useMockApi ? new MockAnalysisApi() : new HttpAnalysisApi();
  return client;
}
