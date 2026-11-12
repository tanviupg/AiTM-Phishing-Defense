"""
Integration & API tests for Module 4 SOC Dashboard.
Covers:
- Real pipeline integration (Module 1 -> Module 2 -> Module 3 -> Module 4)
- Dashboard overview metrics, threat analysis indicators & chart datasets
- Security event monitoring filtering & search
- Incident management status updates (Open, Investigating, Resolved)
- Session containment revocation (HTTP 401 verification)
- Hardening overview & checklist updates
- Explicit fallback provenance tagging when live modules are unavailable
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from module3_hardening.database import init_db, reset_test_data
from module4_soc_dashboard.backend.app import create_app
from module4_soc_dashboard.backend.integration_service import ModuleIntegrationService


@pytest.fixture()
def live_client():
    init_db()
    reset_test_data()
    service = ModuleIntegrationService(prefer_live_api=False, force_fallback=False)
    app = create_app(integration_service=service)
    return TestClient(app)


@pytest.fixture()
def fallback_client():
    service = ModuleIntegrationService(force_fallback=True)
    app = create_app(integration_service=service)
    return TestClient(app)


def test_frontend_index_served(live_client):
    res = live_client.get("/")
    assert res.status_code == 200
    assert "AiTM Sentinel" in res.text


def test_system_status_reports_direct_pipeline(live_client):
    res = live_client.get("/api/m4/system/status")
    assert res.status_code == 200
    data = res.json()
    assert data["integration_mode"] == "DIRECT_PIPELINE"
    assert data["is_mock_data"] is False
    assert data["modules"]["module1_event_generator"]["available"] is True
    assert data["modules"]["module2_detection_engine"]["available"] is True
    assert data["modules"]["module3_hardening_api"]["available"] is True


def test_dashboard_overview_and_analytics_from_real_pipeline(live_client):
    res = live_client.get("/api/m4/dashboard/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["is_mock_data"] is False
    assert data["overview"]["total_events"] >= 2
    assert data["overview"]["total_phishing_alerts"] >= 1
    assert "threat_analysis" in data
    assert "tls_certificate_anomalies" in data["threat_analysis"]
    assert "suspicious_redirect_chains" in data["threat_analysis"]
    assert "session_anomalies" in data["threat_analysis"]
    assert "token_replay_indicators" in data["threat_analysis"]
    assert len(data["charts"]["severity_distribution"]) == 4
    assert len(data["charts"]["risk_score_distribution"]) == 4
    assert len(data["charts"]["detection_category_distribution"]) == 4


def test_event_monitoring_filters_and_pipeline_analyze(live_client):
    payload = {
        "session_id": "M4-TEST-SES-900",
        "auth_result": "success",
        "redirect_count": 4,
        "redirect_chain": [
            "portal.corp.local",
            "proxy-relay.attacker.invalid",
            "login.microsoftonline.com",
            "portal.corp.local",
        ],
        "tls_anomaly": True,
        "replay_indicator": True,
        "source_ip": "198.51.100.88",
        "device_id": "DEV-TEST-M4",
        "scenario": "suspicious_simulation",
        "user_alias": "testuser@lab.local",
    }
    analyze_res = live_client.post("/api/m4/pipeline/analyze", json=payload)
    assert analyze_res.status_code == 200
    analyzed = analyze_res.json()
    assert analyzed["risk_level"] == "HIGH"
    assert analyzed["is_mock_data"] is False

    # Filter events by search & severity
    ev_res = live_client.get("/api/m4/events?severity=High&search=M4-TEST-SES-900")
    assert ev_res.status_code == 200
    items = ev_res.json()["items"]
    assert len(items) == 1
    assert items[0]["session_id"] == "M4-TEST-SES-900"
    assert items[0]["risk_score"] >= 60
    assert items[0]["incident_status"] == "Open"


def test_incident_management_status_updates_and_revocation(live_client):
    # Run Module 3 scenario SCN-004 (Synthetic Session Replay)
    run_res = live_client.post("/api/m4/lab/scenarios/SCN-004/run")
    assert run_res.status_code == 200
    inc_id = run_res.json()["generated_incident_id"]
    assert inc_id is not None

    # Fetch incident details
    det_res = live_client.get(f"/api/m4/incidents/{inc_id}")
    assert det_res.status_code == 200
    assert det_res.json()["status"] == "Open"

    # Update status to Investigating -> Resolved
    for target_status in ("Investigating", "Resolved"):
        patch_res = live_client.patch(
            f"/api/m4/incidents/{inc_id}/status",
            json={"status": target_status},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["new_status"] == target_status

    # Non-existent incident returns 404
    missing_res = live_client.patch("/api/m4/incidents/INC-DOES-NOT-EXIST/status", json={"status": "Resolved"})
    assert missing_res.status_code == 404

    # Session revocation containment check
    rev_res = live_client.post("/api/m4/sessions/SES-LAB-004/revoke")
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "revoked"

    access_res = live_client.post("/api/m4/sessions/SES-LAB-004/test_access")
    assert access_res.status_code == 200
    assert access_res.json()["status_code"] == 401
    assert access_res.json()["containment_proven"] is True


def test_hardening_integration_and_checklist(live_client):
    res = live_client.get("/api/m4/hardening/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["is_mock_data"] is False
    assert len(data["auth_methods"]) >= 5
    assert "protocol_breakdown" in data["origin_binding"]
    assert len(data["checklist"]) >= 8

    item_id = data["checklist"][0]["item_id"]
    upd = live_client.patch(f"/api/m4/hardening/checklist/{item_id}", json={"status": "Verified"})
    assert upd.status_code == 200
    assert upd.json()["status"] == "Verified"


def test_fallback_mode_explicitly_labelled_as_mock(fallback_client):
    status = fallback_client.get("/api/m4/system/status").json()
    assert status["integration_mode"] == "SYNTHETIC_FALLBACK"
    assert status["is_mock_data"] is True

    overview = fallback_client.get("/api/m4/dashboard/overview").json()
    assert overview["is_mock_data"] is True
    assert overview["data_source"] == "SYNTHETIC_FALLBACK"

    events = fallback_client.get("/api/m4/events").json()
    assert events["is_mock_data"] is True
    assert all(e["is_mock_data"] is True for e in events["items"])
