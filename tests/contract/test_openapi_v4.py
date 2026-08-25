from src.main import app


def test_openapi_exposes_v4_as_a_separate_security_contract() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v4/analyses"]["post"]

    request_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    accepted_ref = operation["responses"]["202"]["content"]["application/json"]["schema"]["$ref"]
    assert request_ref.endswith("/SecurityTriageCreateRequestV4")
    assert response_ref.endswith("/SecurityScopeResponseV4")
    assert accepted_ref.endswith("/SecurityAnalysisAcceptedResponseV4")

    components = schema["components"]["schemas"]
    assert set(components["ScopeDecisionV4"]["enum"]) == {
        "IN_SCOPE",
        "NEED_MORE_INFO",
        "OUT_OF_SCOPE_GENERAL_FACT_CHECK",
    }
    assert components["SecurityTriageCreateRequestV4"]["additionalProperties"] is False
    assert "consent_to_scan_urls" not in components["SecurityTriageCreateRequestV4"]["properties"]
    assert "claims" not in components["SecurityScopeResponseV4"]["properties"]
    assert components["SecurityTriageCreateRequestV4"]["properties"]["execution_mode"]["default"] == "inline"
    assert "kind" in components["SecurityAnalysisEventV4"]["properties"]
    assert "reviewed_security_memory" in components["SecurityEvidenceTypeV4"]["enum"]
    assert "domain_familiarity" in components["SecurityEvidenceTypeV4"]["enum"]
    assert "DomainFamiliarityDetailsV4" in components
    evidence = components["SecurityEvidenceV4"]["properties"]
    assert evidence["domain_familiarity"]["anyOf"][0]["$ref"].endswith("/DomainFamiliarityDetailsV4")
    assert "security_memory_lookup" in components["SecurityInvestigationToolV4"]["enum"]


def test_openapi_exposes_structured_report_resolution_and_remediation() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v4/admin/reports/{report_id}/decision"]["post"]
    request_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert request_ref.endswith("/SecurityReportDecisionRequestV4")
    assert response_ref.endswith("/SecurityReportAdminRecordV4")

    components = schema["components"]["schemas"]
    assert components["SecurityReportResolutionV4"]["enum"] == [
        "confirm_safe",
        "mark_false_positive",
        "confirm_malicious",
        "needs_more_information",
        "no_change",
    ]
    assert components["SecurityReportRemediationActionV4"]["enum"] == [
        "none",
        "update_memory",
        "add_to_whitelist",
        "propose_blacklist",
    ]
    assert components["SecurityReportRemediationStatusV4"]["enum"] == [
        "not_requested",
        "pending",
        "executed",
        "failed",
    ]

    request = components["SecurityReportDecisionRequestV4"]
    assert request["additionalProperties"] is False
    assert request["properties"]["remediation_action"]["default"] == "none"
    assert request["properties"]["resolution"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportResolutionV4"
    )
    assert request["properties"]["whitelist_entry"]["anyOf"][0]["$ref"].endswith(
        "/WhitelistCreateRequestV4"
    )
    assert request["properties"]["blacklist_proposal"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportBlacklistProposalV4"
    )

    record = components["SecurityReportRecordV4"]["properties"]
    assert record["remediation_status"]["default"] == "not_requested"
    assert record["remediation_reference"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportRemediationReferenceV4"
    )

    audit = components["SecurityAdminAuditEventV4"]["properties"]
    assert audit["report_details"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportAuditDetailsV4"
    )
    audit_details = components["SecurityReportAuditDetailsV4"]["properties"]
    assert audit_details["resolution"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportResolutionV4"
    )
    assert audit_details["remediation_reference"]["anyOf"][0]["$ref"].endswith(
        "/SecurityReportRemediationReferenceV4"
    )


def test_openapi_exposes_v4_blacklist_lifecycle_without_public_v3_expansion() -> None:
    schema = app.openapi()
    paths = schema["paths"]
    assert {
        "/api/v4/admin/blacklist/page",
        "/api/v4/admin/blacklist/proposals",
        "/api/v4/admin/blacklist/{blacklist_id}",
        "/api/v4/admin/blacklist/{blacklist_id}/disable-proposals",
        "/api/v4/admin/blacklist/{blacklist_id}/audit",
        "/api/v4/admin/blacklist/actions/{action_id}/decision",
    } <= set(paths)
    assert not any(path.startswith("/api/v3/admin/blacklist") for path in paths)

    components = schema["components"]["schemas"]
    assert components["SecurityBlacklistLifecycleV4"]["enum"] == ["active", "disabled"]
    assert components["SecurityBlacklistActionV4"]["enum"] == [
        "add_to_blacklist",
        "disable_blacklist",
    ]
    assert "blacklist" in components["SecurityAuditResourceV4"]["enum"]
    proposal = paths["/api/v4/admin/blacklist/proposals"]["post"]
    assert proposal["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/SecurityBlacklistProposalRequestV4"
    )
