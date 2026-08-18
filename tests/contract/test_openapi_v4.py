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
    assert "security_memory_lookup" in components["SecurityInvestigationToolV4"]["enum"]
