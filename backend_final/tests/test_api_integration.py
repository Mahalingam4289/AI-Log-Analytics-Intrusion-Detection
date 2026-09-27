"""
tests/test_api_integration.py — integration tests that exercise the real
FastAPI app (auth, protected routes, alert workflow, settings) via
TestClient. The app's startup event runs for real here (bootstrapping
models/data if missing), so the first run of this file may take up to a
minute; subsequent runs are fast once saved_models/ and data/ exist.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["SENTINEL_REQUIRE_AUTH"] = "true"
os.environ["SENTINEL_USE_REDIS"] = "false"
os.environ.setdefault("SENTINEL_ADMIN_USER", "admin")
os.environ.setdefault("SENTINEL_ADMIN_PASSWORD", "admin123")

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health_check_is_public(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_success(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["username"] == "admin"


def test_login_failure(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_protected_route_without_token_is_401(client):
    resp = client.get("/api/events")
    assert resp.status_code == 401


def test_protected_route_with_token_is_200(client, auth_headers):
    resp = client.get("/api/events?limit=5", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_events_response_has_expected_fields(client, auth_headers):
    resp = client.get("/api/events?limit=1", headers=auth_headers)
    body = resp.json()
    if body:  # only assert shape if any events exist yet
        event = body[0]
        for field in ("event_id", "timestamp", "risk_score", "severity", "threat_category"):
            assert field in event


def test_stats_endpoint(client, auth_headers):
    resp = client.get("/api/stats", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    for field in ("total_events", "total_anomalies", "total_attacks", "total_critical", "open_incidents"):
        assert field in body


def test_settings_get_and_patch_roundtrip(client, auth_headers):
    resp = client.get("/api/settings", headers=auth_headers)
    assert resp.status_code == 200
    original = resp.json()["alert_threshold"]

    resp2 = client.patch("/api/settings", json={"alert_threshold": 55}, headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.json()["alert_threshold"] == 55

    # restore original value so other tests / a real session aren't affected
    client.patch("/api/settings", json={"alert_threshold": original}, headers=auth_headers)


def test_settings_patch_requires_auth(client):
    resp = client.patch("/api/settings", json={"alert_threshold": 55})
    assert resp.status_code == 401


def test_alert_patch_invalid_status_rejected(client, auth_headers):
    resp = client.get("/api/alerts?limit=1", headers=auth_headers)
    alerts = resp.json()
    if not alerts:
        pytest.skip("no alerts generated yet in this test run")
    alert_id = alerts[0]["alert_id"]
    bad = client.patch(f"/api/alerts/{alert_id}", json={"status": "NOT_A_REAL_STATUS"}, headers=auth_headers)
    assert bad.status_code == 400


def test_alert_patch_updates_status_and_notes(client, auth_headers):
    resp = client.get("/api/alerts?limit=1", headers=auth_headers)
    alerts = resp.json()
    if not alerts:
        pytest.skip("no alerts generated yet in this test run")
    alert_id = alerts[0]["alert_id"]

    patch = client.patch(f"/api/alerts/{alert_id}",
                          json={"status": "INVESTIGATING", "analyst_notes": "test note"},
                          headers=auth_headers)
    assert patch.status_code == 200

    check = client.get("/api/alerts?limit=5", headers=auth_headers)
    updated = next((a for a in check.json() if a["alert_id"] == alert_id), None)
    assert updated is not None
    assert updated["status"] == "INVESTIGATING"
    assert updated["analyst_notes"] == "test note"


def test_events_csv_export_returns_csv(client, auth_headers):
    resp = client.get("/api/events/export.csv", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


def test_alerts_csv_export_returns_csv(client, auth_headers):
    resp = client.get("/api/alerts/export.csv", headers=auth_headers)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]


def test_user_summary_endpoint_handles_unknown_entity(client, auth_headers):
    resp = client.get("/api/users/definitely_not_a_real_user_xyz/summary", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == 0
    assert body["attack_breakdown"] == []
