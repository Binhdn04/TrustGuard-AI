import { describe, expect, it } from "vitest";

import { HttpSecurityAnalysisApi } from "@/lib/api/http-security-analysis-api";
import type { SecurityAnalysisApi } from "@/lib/api/security-analysis-api.types";
import type {
  SecurityCapabilitiesResponseV4,
  SecurityReportAdminRecordV4,
  SecurityReportPageV4,
} from "@/types/generated/api-v4";

const requiredMethods = [
  "getCapabilities",
  "createAnalysis",
  "getAnalysis",
  "getAdminAnalysis",
  "listAnalyses",
  "pageAnalyses",
  "getConversation",
  "listConversations",
  "getAnalysisEvents",
  "createWebSocketTicket",
  "reportAnalysis",
  "listReports",
  "createAppeal",
  "listAnalysisAppeals",
  "listAdminReports",
  "decideAdminReport",
  "listAdminAppeals",
  "decideAdminAppeal",
  "createBrand",
  "listBrands",
  "pageBrands",
  "disableBrand",
  "createWhitelist",
  "listWhitelist",
  "pageWhitelist",
  "disableWhitelist",
  "listSecurityMemory",
  "pageSecurityMemory",
  "correctSecurityMemory",
  "listSecurityMemoryAudit",
  "listSecurityCampaigns",
  "pageSecurityCampaigns",
  "getSecurityCampaign",
  "reviewSecurityCampaign",
  "listSecurityCampaignAudit",
  "listDomainIntelligence",
  "listThreatIntelligence",
  "listAdminAudit",
] satisfies Array<keyof SecurityAnalysisApi>;

describe("Security API v4 contract", () => {
  it("exposes every legacy and WP9A client operation", () => {
    const api: SecurityAnalysisApi = new HttpSecurityAnalysisApi("http://backend.test");

    for (const method of requiredMethods) {
      expect(api[method], method).toBeTypeOf("function");
    }
  });

  it("keeps capability and admin page records aligned with the v4 response shape", () => {
    const capabilities = {
      contract_version: "v4",
      product_profile: "security_triage_vnext",
      release_profile: "pre_cutover",
      conversation_resume: true,
      admin_feedback_review: true,
      intelligence_explorer: true,
      unified_v4_audit: true,
      admin_action_contract: "v3",
      executable_admin_actions: ["add_to_blacklist"],
      deferred_admin_actions: ["block_domain"],
      compatibility_contracts: ["v2", "v3", "v4"],
    } satisfies SecurityCapabilitiesResponseV4;
    const report = {
      contract_version: "v4",
      report_id: "report-1",
      analysis_id: "analysis-1",
      owner_id: "owner-1",
      reason: "Suspicious verdict",
      comment: null,
      status: "processed",
      decision: "approved",
      reviewer_id: "admin-1",
      review_note: "Confirmed",
      created_at: "2026-08-13T00:00:00Z",
      reviewed_at: "2026-08-13T01:00:00Z",
    } satisfies SecurityReportAdminRecordV4;
    const page = {
      contract_version: "v4",
      items: [report],
      total: 1,
      limit: 25,
      offset: 0,
    } satisfies SecurityReportPageV4;

    expect(capabilities.compatibility_contracts).toContain("v4");
    expect(page.items[0].owner_id).toBe("owner-1");
  });
});
