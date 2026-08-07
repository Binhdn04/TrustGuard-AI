from src.main import app


def test_openapi_freezes_v3_paths_and_models() -> None:
    schema = app.openapi()
    expected_paths = {
        "/api/v3/analyses",
        "/api/v3/analyses/{analysis_id}",
        "/api/v3/analyses/{analysis_id}/events",
        "/api/v3/analyses/{analysis_id}/reports",
        "/api/v3/ws-tickets",
        "/api/v3/analyses/{analysis_id}/appeals",
        "/api/v3/appeals/{appeal_id}",
        "/api/v3/admin/appeals",
        "/api/v3/admin/appeals/{appeal_id}/decision",
        "/api/v3/admin/actions/{action_id}/decision",
        "/api/v3/admin/actions",
        "/api/v3/admin/actions/{action_id}",
        "/api/v3/admin/campaigns",
        "/api/v3/admin/campaigns/{campaign_id}",
        "/api/v3/admin/metrics",
    }
    assert expected_paths <= set(schema["paths"])

    components = schema["components"]["schemas"]
    event_items = components["AnalysisEventPageV3"]["properties"]["events"]["items"]
    assert event_items["discriminator"]["propertyName"] == "event_type"
    assert set(components["ReviewedAction"]["enum"]) == {
        "add_to_blacklist",
        "disable_blacklist",
        "block_domain",
        "publish_broad_warning",
        "none",
    }


def test_v2_openapi_contract_is_not_retyped_as_v3() -> None:
    schema = app.openapi()
    v2_detail = schema["paths"]["/api/v2/analyses/{analysis_id}"]["get"]
    v3_detail = schema["paths"]["/api/v3/analyses/{analysis_id}"]["get"]
    assert v2_detail["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/AnalysisResponse")
    assert v3_detail["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/AnalysisResponseV3"
    )
