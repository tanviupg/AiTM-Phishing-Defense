"""
Unit & Integration Tests for AiTM Sentinel 8-Screen REST API (v2).
Tests all 8 screen endpoints, SQLite persistence, scenario runner,
containment verification, and interactive training quiz.
"""

import sys
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
from module3_hardening.api import app
from module3_hardening.database import init_db, reset_test_data

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_clean_db():
    """Ensure clean database state before each test."""
    init_db()
    yield


def test_api_health():
    response = client.get("/api/defense/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "AiTM Sentinel" in data["platform"]


def test_screen_01_dashboard_summary():
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "summary_cards" in data
    assert "active_alerts" in data["summary_cards"]
    assert "detection_breakdown" in data
    assert data["environment"] == "ISOLATED LAB"


def test_screen_02_lab_scenarios_and_execution():
    # 1. List scenarios
    list_res = client.get("/api/v1/lab/scenarios")
    assert list_res.status_code == 200
    scenarios = list_res.json()
    assert len(scenarios) == 6

    # 2. Run Normal scenario (SCN-001)
    run_norm = client.post("/api/v1/lab/scenarios/SCN-001/run")
    assert run_norm.status_code == 200
    norm_data = run_norm.json()
    assert norm_data["test_passed"] is True
    assert norm_data["observed_outcome"]["risk_level"] == "LOW"
    assert norm_data["formula_scoring"]["score_out_of_100"] < 60

    # 3. Run Replay scenario (SCN-004)
    run_replay = client.post("/api/v1/lab/scenarios/SCN-004/run")
    assert run_replay.status_code == 200
    replay_data = run_replay.json()
    assert replay_data["observed_outcome"]["risk_level"] == "HIGH"
    assert replay_data["formula_scoring"]["variables"]["S"] == 1
    assert replay_data["formula_scoring"]["score_out_of_100"] >= 60

    # 4. Run Post-Revocation containment scenario (SCN-005)
    run_contain = client.post("/api/v1/lab/scenarios/SCN-005/run")
    assert run_contain.status_code == 200
    contain_data = run_contain.json()
    assert contain_data["observed_outcome"]["containment_proven"] is True


def test_screen_03_event_explorer():
    # Populate events via scenario run
    client.post("/api/v1/lab/scenarios/SCN-002/run")
    res = client.get("/api/v1/events?limit=10")
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    assert isinstance(events[0]["redirect_chain"], list)


def test_screen_04_incident_investigation_and_dossier():
    # Run suspicious scenario to create incident
    client.post("/api/v1/lab/scenarios/SCN-004/run")
    inc_res = client.get("/api/v1/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) >= 1

    inc_id = incidents[0]["incident_id"]
    det_res = client.get(f"/api/v1/incidents/{inc_id}")
    assert det_res.status_code == 200
    det = det_res.json()
    assert "formula_breakdown" in det
    assert "timeline" in det

    # Update status to Investigating
    patch_res = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "Investigating"})
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "Investigating"

    # Export Dossier
    export_res = client.get(f"/api/v1/incidents/{inc_id}/export")
    assert export_res.status_code == 200
    assert "Security Incident Triage Dossier" in export_res.text
    assert "R = 30D + 20C + 25S + 15E + 10A" in export_res.text


def test_screen_05_session_management_and_revocation():
    session_id = "SES-TEST-REVOKE-01"
    from module3_hardening.database import record_session
    record_session(session_id, "test@lab.local", "TestClient", "127.0.0.1", "manual_test")

    # Before revocation: access should be granted
    access_before = client.post(f"/api/v1/sessions/{session_id}/test_access")
    assert access_before.status_code == 200
    assert access_before.json()["access_granted"] is True

    # Revoke session
    rev_res = client.post(f"/api/v1/sessions/{session_id}/revoke", json={"performed_by": "SOC-Lead"})
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "revoked"

    # After revocation: access should be blocked (HTTP 401)
    access_after = client.post(f"/api/v1/sessions/{session_id}/test_access")
    assert access_after.status_code == 200
    assert access_after.json()["access_granted"] is False
    assert access_after.json()["status_code"] == 401
    assert access_after.json()["containment_proven"] is True


def test_screen_06_detection_rules():
    rules_res = client.get("/api/v1/rules")
    assert rules_res.status_code == 200
    rules = rules_res.json()
    assert len(rules) >= 5
    rule_ids = [r["rule_id"] for r in rules]
    assert "DET-001" in rule_ids
    assert "DET-003" in rule_ids

    # Update rule weight
    patch_res = client.patch("/api/v1/rules/DET-001", json={"weight": 35})
    assert patch_res.status_code == 200
    assert patch_res.json()["weight"] == 35


def test_screen_07_hardening_checklist():
    chk_res = client.get("/api/v1/hardening/checklist")
    assert chk_res.status_code == 200
    items = chk_res.json()
    assert len(items) >= 8

    # Update item status
    item_id = items[0]["item_id"]
    patch_res = client.patch(f"/api/v1/hardening/checklist/{item_id}", json={"status": "Verified", "notes": "Tested in lab."})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Verified"


def test_screen_08_training_and_quiz():
    mod_res = client.get("/api/v1/training/modules")
    assert mod_res.status_code == 200
    mod_data = mod_res.json()
    assert len(mod_data["lessons"]) == 3
    assert len(mod_data["questions"]) == 8

    # Test quiz verification
    # Submit correct answers for Q-01 through Q-08
    answers = {
        "Q-01": 1,
        "Q-02": 1,
        "Q-03": 1,
        "Q-04": 2,
        "Q-05": 1,
        "Q-06": 1,
        "Q-07": 1,
        "Q-08": 1,
    }
    quiz_res = client.post("/api/v1/training/quiz/verify", json={"answers": answers})
    assert quiz_res.status_code == 200
    q_data = quiz_res.json()
    assert q_data["score_percentage"] == 100.0
    assert q_data["passed"] is True
    assert q_data["certificate_eligible"] is True
