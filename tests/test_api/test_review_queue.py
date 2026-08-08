import pytest

USER_HEADERS = {"Authorization": "Bearer dev-user-token"}
ADMIN_HEADERS = {"Authorization": "Bearer dev-admin-token"}

@pytest.mark.asyncio
async def test_user_report_review_queue_e2e(client):
    # 1. User creates an analysis
    created = await client.post(
        "/api/v3/analyses",
        headers=USER_HEADERS,
        json={"message": "Kiểm tra abc.com", "consent_to_scan_urls": True},
    )
    assert created.status_code == 202
    analysis_id = created.json()["analysis_id"]

    # 2. User submits a report
    report = await client.post(
        f"/api/v3/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
        json={"reason": "Kết quả sai", "comment": "Bỏ qua abc.com"},
    )
    assert report.status_code == 201
    
    # User can see their report in 'submitted' status
    user_reports = await client.get(
        f"/api/v3/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
    )
    assert user_reports.status_code == 200
    reports = user_reports.json()
    assert len(reports) == 1
    assert reports[0]["status"] == "submitted"

    # 3. Admin views the review queue
    admin_queue = await client.get(
        "/api/v3/admin/review-queue",
        headers=ADMIN_HEADERS,
    )
    assert admin_queue.status_code == 200
    queue_items = admin_queue.json()
    
    target_item = next((i for i in queue_items if i["analysis_id"] == analysis_id), None)
    assert target_item is not None
    assert target_item["status"] == "submitted"
    item_id = target_item["item_id"]

    # 4. Admin starts reviewing
    start_review = await client.post(
        f"/api/v3/admin/review-queue/{item_id}/start-review",
        headers=ADMIN_HEADERS,
    )
    assert start_review.status_code == 204

    # User sees status changed to 'reviewing'
    user_reports = await client.get(
        f"/api/v3/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
    )
    assert user_reports.json()[0]["status"] == "reviewing"

    # 5. Admin makes a decision
    decision = await client.post(
        f"/api/v3/admin/review-queue/{item_id}/decision",
        headers=ADMIN_HEADERS,
        json={"decision": "dismissed", "note": "Không đủ bằng chứng"},
    )
    assert decision.status_code == 204

    # User sees status changed to 'processed'
    user_reports = await client.get(
        f"/api/v3/analyses/{analysis_id}/reports",
        headers=USER_HEADERS,
    )
    assert user_reports.json()[0]["status"] == "processed"
