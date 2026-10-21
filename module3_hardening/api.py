"""
AiTM Sentinel - Comprehensive Defense & Hardening REST API (Module 3 & System Core).
Exposes endpoints for the entire 8-Screen Web SOC Architecture:
- Screen 01: Command Centre (/api/v1/dashboard/summary)
- Screen 02: Detection Lab (/api/v1/lab/scenarios, /api/v1/lab/scenarios/{id}/run, /api/v1/lab/reset)
- Screen 03: Event Explorer (/api/v1/events)
- Screen 04: Incident Investigation (/api/v1/incidents, /api/v1/incidents/{id}, /api/v1/incidents/{id}/export)
- Screen 05: Session Management (/api/v1/sessions, /api/v1/sessions/{id}/revoke, /api/v1/sessions/{id}/test_access)
- Screen 06: Detection Rules (/api/v1/rules, /api/v1/rules/{id})
- Screen 07: Security Hardening (/api/v1/hardening/checklist, /api/v1/hardening/checklist/{id})
- Screen 08: User Training & Certification (/api/v1/training/modules, /api/v1/training/quiz/verify)
"""

import sys
from typing import Any, Optional
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from fastapi import FastAPI, HTTPException, Body, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.hardening_checklist import HardeningChecklist
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase
from module3_hardening.database import (
    get_db_connection, record_event, record_incident,
    record_session, revoke_session_db, verify_session_access,
    reset_test_data, init_db
)
from module3_hardening.training_quiz import LESSONS, QUIZ_QUESTIONS, evaluate_quiz_submission
from module3_hardening.lab_scenarios import LAB_SCENARIOS, list_scenarios, run_lab_scenario

# Optional imports from Module 2 for unified pipeline evaluation
try:
    from module2_detection.detector import AiTMDetector
    from module2_detection.session_tracker import SessionTracker
    from module2_detection.tls_analyzer import TLSAnalyzer
    MODULE2_AVAILABLE = True
except ImportError:
    MODULE2_AVAILABLE = False

engine = HardeningEngine()
checklist = HardeningChecklist()
kb = AuthDefenseKnowledgeBase()

if MODULE2_AVAILABLE:
    shared_detector = AiTMDetector()
    shared_session_tracker = SessionTracker()
    shared_tls_analyzer = TLSAnalyzer()
else:
    shared_detector = None
    shared_session_tracker = None
    shared_tls_analyzer = None


def get_recommendations_for_event(detection_result: dict[str, Any]) -> dict[str, Any]:
    """Direct Python interface to evaluate detection result and return defense plan dictionary."""
    plan = engine.evaluate_detection(detection_result)
    return plan.to_dict()


def get_hardening_checklist_data() -> dict[str, Any]:
    """Direct Python interface to retrieve the machine-readable hardening checklist."""
    return checklist.to_dict()


def get_auth_methods_matrix() -> list[dict[str, Any]]:
    """Direct Python interface to retrieve the authentication methods comparison."""
    return [p.to_dict() for p in kb.get_all_profiles()]


if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="AiTM Sentinel - Defensive Detection & Response Platform",
        description="Comprehensive REST API for DeepCytes Fellowship Track H (Adversary-in-the-Middle Phishing Defense)",
        version="2.0.0",
    )

    # Enable CORS for local React/Vite development (default Vite port 5173 / Next.js 3000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # =========================================================================
    # SYSTEM & DASHBOARD UI ROOT
    # =========================================================================

    @app.get("/api/defense/health")
    def health_check() -> dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "platform": "AiTM Sentinel Defensive Platform",
            "fellowship_track": "Track H: Adversary-in-the-Middle (AiTM) Phishing Defense",
            "environment": "ISOLATED_LAB",
            "telemetry_type": "Synthetic & Controlled Relay Telemetry",
            "module_1": "Complete (Lab Proxy & Event Generation)",
            "module_2": "Complete (Multi-Signal Detection & Risk Formula R=30D+20C+25S+15E+10A)",
            "module_3": "Complete (FIDO2/Passkey Defense, Hardening, Containment & API Core)",
            "module_4": "Frontend Ready (Consumes /api/v1/* endpoints)",
        }

    @app.get("/", response_class=HTMLResponse)
    def get_dashboard() -> HTMLResponse:
        """Serves the interactive SOC Detection & Hardening Web UI."""
        dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
        if not dashboard_path.exists():
            return HTMLResponse("<h2>Dashboard HTML not found.</h2>", status_code=404)
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))

    # =========================================================================
    # SCREEN 01: COMMAND CENTRE (/api/v1/dashboard/summary)
    # =========================================================================

    @app.get("/api/v1/dashboard/summary")
    def get_dashboard_summary() -> dict[str, Any]:
        """
        Screen 01: Command Centre summary metrics.
        Returns active alerts, total events processed, suspicious sessions, revoked sessions,
        detection breakdown by anomaly type, and recent incidents.
        """
        conn = get_db_connection()
        c = conn.cursor()

        # Count events
        c.execute("SELECT COUNT(*) as cnt FROM events")
        events_processed = c.fetchone()["cnt"]

        # Count incidents by status
        c.execute("SELECT COUNT(*) as cnt FROM incidents WHERE status = 'Open' OR status = 'Investigating'")
        active_alerts = c.fetchone()["cnt"]

        # Count total incidents
        c.execute("SELECT COUNT(*) as cnt FROM incidents")
        total_incidents = c.fetchone()["cnt"]

        # Count suspicious sessions and revoked sessions
        c.execute("SELECT COUNT(*) as cnt FROM sessions WHERE replay_indicator = 1 OR status = 'revoked'")
        suspicious_sessions = c.fetchone()["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM sessions WHERE status = 'revoked'")
        revoked_sessions = c.fetchone()["cnt"]

        # Recent incidents
        c.execute("""
            SELECT incident_id, title, severity, risk_score, risk_level, status, user_alias, scenario, created_at
            FROM incidents
            ORDER BY created_at DESC LIMIT 6
        """)
        recent_incidents = [dict(row) for row in c.fetchall()]

        # Detection breakdown from events
        c.execute("SELECT COUNT(*) as cnt FROM events WHERE tls_anomaly = 1")
        tls_anomalies = c.fetchone()["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM events WHERE redirect_count > 3")
        redirect_anomalies = c.fetchone()["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM events WHERE replay_indicator = 1")
        replay_anomalies = c.fetchone()["cnt"]

        conn.close()

        return {
            "environment": "ISOLATED LAB",
            "telemetry_source": "Controlled Mock IdP & Synthetic Relay Telemetry",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary_cards": {
                "active_alerts": active_alerts,
                "events_processed": events_processed,
                "suspicious_sessions": suspicious_sessions,
                "revoked_sessions": revoked_sessions,
                "total_incidents": total_incidents,
            },
            "detection_breakdown": {
                "domain_tls_anomalies": tls_anomalies,
                "redirect_chain_anomalies": redirect_anomalies,
                "session_replay_indicators": replay_anomalies,
            },
            "recent_incidents": recent_incidents,
        }

    # =========================================================================
    # SCREEN 02: DETECTION LAB (/api/v1/lab/*)
    # =========================================================================

    @app.get("/api/v1/lab/scenarios")
    def get_lab_scenarios() -> list[dict[str, Any]]:
        """Screen 02: List all 6 controlled test scenarios."""
        return list_scenarios()

    @app.post("/api/v1/lab/scenarios/{scenario_id}/run")
    def execute_lab_scenario(scenario_id: str) -> dict[str, Any]:
        """
        Screen 02: Run a controlled lab scenario end-to-end:
        Generates synthetic telemetry -> Evaluates M2 detection & R formula -> Generates M3 plan ->
        Logs to SQLite -> Evaluates whether observed matched expected.
        """
        try:
            return run_lab_scenario(
                scenario_id=scenario_id,
                detector=shared_detector,
                hardening_engine=engine,
                session_tracker=shared_session_tracker,
                tls_analyzer=shared_tls_analyzer,
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Scenario execution error: {str(e)}")

    @app.post("/api/v1/lab/reset")
    def reset_lab_telemetry() -> dict[str, Any]:
        """Screen 02: Resets isolated lab database to clean baseline."""
        return reset_test_data()

    # =========================================================================
    # SCREEN 03: EVENT EXPLORER (/api/v1/events)
    # =========================================================================

    @app.get("/api/v1/events")
    def get_explorer_events(
        severity: Optional[str] = None,
        scenario: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Screen 03: Event Explorer.
        Query normalized security events with filtering by severity, scenario, and text search.
        """
        conn = get_db_connection()
        c = conn.cursor()

        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if scenario:
            query += " AND scenario = ?"
            params.append(scenario)
        if search:
            query += " AND (event_id LIKE ? OR session_id LIKE ? OR user_alias LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

        results = []
        for r in rows:
            d = dict(r)
            d["redirect_chain"] = json.loads(d["redirect_chain"]) if d["redirect_chain"] else []
            d["raw_json"] = json.loads(d["raw_json"]) if d["raw_json"] else {}
            results.append(d)

        # If database is empty, seed from sample_events.json
        if not results:
            sample_path = ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"
            if sample_path.exists():
                with open(sample_path, "r", encoding="utf-8") as f:
                    samples = json.load(f)
                    for s in samples:
                        record_event(s, severity="High" if s.get("scenario") == "suspicious_simulation" else "Low")
                return get_explorer_events(severity=severity, scenario=scenario, search=search, limit=limit)

        return results

    # =========================================================================
    # SCREEN 04: INCIDENT INVESTIGATION (/api/v1/incidents/*)
    # =========================================================================

    @app.get("/api/v1/incidents")
    def list_incidents(status: Optional[str] = None) -> list[dict[str, Any]]:
        """Screen 04: List all flagged security incidents."""
        conn = get_db_connection()
        c = conn.cursor()
        if status:
            c.execute("SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            c.execute("SELECT * FROM incidents ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()

        results = []
        for r in rows:
            d = dict(r)
            d["signals"] = json.loads(d["signals_json"]) if d.get("signals_json") else {}
            d["formula_breakdown"] = json.loads(d["formula_breakdown_json"]) if d.get("formula_breakdown_json") else {}
            d["recommendations"] = json.loads(d["recommendations_json"]) if d.get("recommendations_json") else []
            results.append(d)
        return results

    @app.get("/api/v1/incidents/{incident_id}")
    def get_incident_details(incident_id: str) -> dict[str, Any]:
        """Screen 04: Retrieve deep incident triage details, signals, formula breakdown, and timeline."""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        row = c.fetchone()

        if not row:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

        incident = dict(row)
        incident["signals"] = json.loads(incident["signals_json"]) if incident.get("signals_json") else {}
        incident["formula_breakdown"] = json.loads(incident["formula_breakdown_json"]) if incident.get("formula_breakdown_json") else {}
        incident["recommendations"] = json.loads(incident["recommendations_json"]) if incident.get("recommendations_json") else []

        # Fetch associated events for chronological timeline
        c.execute("SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC", (incident["session_id"],))
        event_rows = c.fetchall()
        timeline = []
        for er in event_rows:
            ed = dict(er)
            timeline.append({
                "event_id": ed["event_id"],
                "timestamp": ed["timestamp"],
                "stage": "Initial Phishing Inbound / Redirect" if ed["redirect_count"] > 1 else "Authentication Sign-in",
                "details": f"Observed {ed['redirect_count']} hops from {ed['source_ip']} (TLS Anomaly: {bool(ed['tls_anomaly'])})",
                "raw_event": json.loads(ed["raw_json"]) if ed.get("raw_json") else {},
            })

        # Add simulated replay step to timeline if replay indicator is set
        if incident["signals"].get("replay_indicator"):
            timeline.append({
                "timestamp": incident["updated_at"],
                "stage": "Token Replay & Hijack Attempt",
                "details": f"Synthetic session token reused from divergent external context.",
            })

        incident["timeline"] = timeline

        # Check if session is currently revoked
        c.execute("SELECT status FROM sessions WHERE session_id = ?", (incident["session_id"],))
        sess_row = c.fetchone()
        incident["session_current_status"] = sess_row["status"] if sess_row else "unknown"

        conn.close()
        return incident

    @app.patch("/api/v1/incidents/{incident_id}/status")
    def update_incident_status(incident_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """Screen 04: Update incident triage status (Open, Investigating, Contained, Resolved)."""
        new_status = payload.get("status")
        if not new_status:
            raise HTTPException(status_code=400, detail="Missing 'status' in body.")

        conn = get_db_connection()
        c = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        c.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?", (new_status, now_iso, incident_id))
        conn.commit()
        conn.close()
        return {"incident_id": incident_id, "new_status": new_status, "updated_at": now_iso}

    @app.get("/api/v1/incidents/{incident_id}/export", response_class=PlainTextResponse)
    def export_incident_dossier(incident_id: str) -> str:
        """Screen 04: Exports a ready-to-print Markdown Forensic Incident Dossier for SOC handoff."""
        details = get_incident_details(incident_id)
        signals = details.get("signals", {})
        fb = details.get("formula_breakdown", {})
        recs = details.get("recommendations", [])

        md = f"""# AiTM Sentinel - Security Incident Triage Dossier
**Incident ID**: {details['incident_id']}
**Generated**: {datetime.now(timezone.utc).isoformat()}
**Environment**: DeepCytes Fellowship Track H Isolated Lab
**Severity**: {details['severity']} | **Risk Score**: {details['risk_score']}/100 ({details['risk_level']})
**Status**: {details['status']} | **Session ID**: {details['session_id']}
**Target User**: {details['user_alias']} | **Scenario**: {details['scenario']}

---

## 1. Executive Summary & Attack Hypothesis
An Adversary-in-the-Middle (AiTM) reverse proxy attack was detected. The user was lured to an attacker-controlled proxy relay which forwarded the legitimate identity provider sign-in page, harvested a post-authentication session token, and attempted session hijacking.

## 2. Explainable Risk-Scoring Formula Breakdown
Scoring Formula: `R = 30D + 20C + 25S + 15E + 10A`
- **D (Unexpected Destination Domain)**: {fb.get('contributions', {}).get('D', 0)} pts (Weight: 30)
- **C (Suspicious Certificate / TLS)**: {fb.get('contributions', {}).get('C', 0)} pts (Weight: 20)
- **S (Session Replay Indicator)**: {fb.get('contributions', {}).get('S', 0)} pts (Weight: 25)
- **E (Suspicious Redirect Sequence)**: {fb.get('contributions', {}).get('E', 0)} pts (Weight: 15)
- **A (Authentication Context Anomaly)**: {fb.get('contributions', {}).get('A', 0)} pts (Weight: 10)
**Total Score**: `{details['risk_score']}/100` (Investigation Threshold: 60)

## 3. Contributing Signals & Telemetry Evidence
- Destination Host Anomaly: {signals.get('unexpected_domain', False)}
- Client TLS / Certificate Anomaly: {signals.get('tls_anomaly', False)}
- Replay Indicator (Token Bifurcation): {signals.get('replay_indicator', False)}
- Multi-Hop Redirect Loop: {signals.get('redirect_anomaly', False)}
- Client Context Shift: {signals.get('context_anomaly', False)}

## 4. Defensive Recommendations & SOC Containment
"""
        for r in recs:
            md += f"- **{r}**\n"

        md += f"""
---
*AiTM Sentinel Defensive Engine - DeepCytes Cyber Labs UK Fellowship*
"""
        return md

    # =========================================================================
    # SCREEN 05: SESSION MANAGEMENT & CONTAINMENT (/api/v1/sessions/*)
    # =========================================================================

    @app.get("/api/v1/sessions")
    def list_sessions(status: Optional[str] = None) -> list[dict[str, Any]]:
        """Screen 05: List synthetic sessions and their active/revoked states."""
        conn = get_db_connection()
        c = conn.cursor()
        if status:
            c.execute("SELECT * FROM sessions WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            c.execute("SELECT * FROM sessions ORDER BY created_at DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    @app.post("/api/v1/sessions/{session_id}/revoke")
    def revoke_session_endpoint(session_id: str, payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
        """
        Screen 05: Revoke synthetic session token.
        Proves defensive containment: invalidates session in DB and updates incident status.
        """
        performed_by = payload.get("performed_by", "SOC-Analyst")
        return revoke_session_db(session_id, performed_by=performed_by)

    @app.post("/api/v1/sessions/{session_id}/test_access")
    def test_session_access_endpoint(session_id: str) -> dict[str, Any]:
        """
        Screen 05: Attempts a simulated client request with the session_id.
        Verifies that access is granted if active, and blocked (HTTP 401) if revoked.
        """
        return verify_session_access(session_id)

    @app.get("/api/v1/containment/audit")
    def get_containment_audit() -> list[dict[str, Any]]:
        """Screen 05: Retrieve containment audit trail log."""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM containment_audit_log ORDER BY timestamp DESC LIMIT 50")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    # =========================================================================
    # SCREEN 06: DETECTION RULES (/api/v1/rules/*)
    # =========================================================================

    @app.get("/api/v1/rules")
    def get_detection_rules() -> list[dict[str, Any]]:
        """Screen 06: List all configurable detection rules (DET-001 to DET-005)."""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM detection_rules ORDER BY rule_id ASC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    @app.patch("/api/v1/rules/{rule_id}")
    def update_detection_rule(rule_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """Screen 06: Update detection rule enabled state or weight threshold."""
        conn = get_db_connection()
        c = conn.cursor()

        enabled = payload.get("enabled")
        weight = payload.get("weight")

        if enabled is not None:
            c.execute("UPDATE detection_rules SET enabled = ?, last_tested = datetime('now') WHERE rule_id = ?", (1 if enabled else 0, rule_id))
        if weight is not None:
            c.execute("UPDATE detection_rules SET weight = ?, last_tested = datetime('now') WHERE rule_id = ?", (int(weight), rule_id))

        conn.commit()
        c.execute("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))
        updated = dict(c.fetchone())
        conn.close()
        return updated

    # =========================================================================
    # SCREEN 07: SECURITY HARDENING CHECKLIST (/api/v1/hardening/checklist/*)
    # =========================================================================

    @app.get("/api/v1/hardening/checklist")
    def get_hardening_checklist_db() -> list[dict[str, Any]]:
        """Screen 07: Retrieve the machine-readable CISA / NIST hardening checklist."""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM hardening_checklist_items ORDER BY item_id ASC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    @app.patch("/api/v1/hardening/checklist/{item_id}")
    def update_checklist_item_status(item_id: str, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """Screen 07: Update checklist item status ('Not assessed', 'In progress', 'Verified', 'Not applicable')."""
        new_status = payload.get("status")
        notes = payload.get("notes")

        conn = get_db_connection()
        c = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        if new_status and notes is not None:
            c.execute("UPDATE hardening_checklist_items SET status = ?, notes = ?, last_reviewed = ? WHERE item_id = ?", (new_status, notes, now_iso, item_id))
        elif new_status:
            c.execute("UPDATE hardening_checklist_items SET status = ?, last_reviewed = ? WHERE item_id = ?", (new_status, now_iso, item_id))
        elif notes is not None:
            c.execute("UPDATE hardening_checklist_items SET notes = ?, last_reviewed = ? WHERE item_id = ?", (notes, now_iso, item_id))

        conn.commit()
        c.execute("SELECT * FROM hardening_checklist_items WHERE item_id = ?", (item_id,))
        updated = dict(c.fetchone())
        conn.close()
        return updated

    # =========================================================================
    # SCREEN 08: USER TRAINING & INTERACTIVE QUIZ (/api/v1/training/*)
    # =========================================================================

    @app.get("/api/v1/training/modules")
    def get_training_modules() -> dict[str, Any]:
        """Screen 08: Retrieve the 3 educational lessons and quiz question set."""
        # Strip correct_index from questions when serving to client to prevent inspection cheating
        sanitized_questions = [
            {
                "question_id": q["question_id"],
                "question": q["question"],
                "options": q["options"],
            }
            for q in QUIZ_QUESTIONS
        ]
        return {
            "title": "AiTM Phishing Defense Awareness & Certification",
            "lessons": LESSONS,
            "questions": sanitized_questions,
            "passing_threshold_pct": 75.0,
        }

    @app.post("/api/v1/training/quiz/verify")
    def verify_training_quiz(submission: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """
        Screen 08: Evaluates submitted quiz answers.
        Body: {"answers": {"Q-01": 1, "Q-02": 1, ...}}
        Returns score percentage, pass/fail status, and explanation for each question.
        """
        answers = submission.get("answers", {})
        return evaluate_quiz_submission(answers)

    # =========================================================================
    # BACKWARD-COMPATIBLE PIPELINE & DEFENSE ENDPOINTS
    # =========================================================================

    @app.post("/api/pipeline/evaluate")
    def evaluate_pipeline(event: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """
        Runs the end-to-end pipeline:
        Event (M1) -> Composite Detection (M2) -> Defense & Hardening Plan (M3).
        """
        try:
            if MODULE2_AVAILABLE and shared_detector:
                detection_result = shared_detector.analyze_event_composite(
                    event,
                    session_tracker=shared_session_tracker,
                    tls_analyzer=shared_tls_analyzer,
                )
            else:
                detection_result = {
                    "session_id": event.get("session_id", "MANUAL"),
                    "risk_score": 0.85 if event.get("scenario") == "suspicious_simulation" else 0.0,
                    "risk_level": "HIGH" if event.get("scenario") == "suspicious_simulation" else "LOW",
                    "signals": {
                        "tls_anomaly": bool(event.get("tls_anomaly")),
                        "redirect_anomaly": bool(event.get("redirect_count", 0) > 3),
                        "replay_indicator": bool(event.get("replay_indicator")),
                    },
                    "composite_explanation": "Evaluated using heuristic pipeline",
                }

            plan = engine.evaluate_detection(detection_result)
            return {
                "event": event,
                "detection": detection_result,
                "plan": plan.to_dict(),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/defense/recommendations")
    def generate_recommendations(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        """Consumes Module 2 detection output and returns structured defense recommendations."""
        try:
            plan = engine.evaluate_detection(payload)
            return plan.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/defense/recommendations/{risk_level}")
    def get_recommendations_by_tier(risk_level: str) -> dict[str, Any]:
        """Quick endpoint to retrieve recommendations for a given tier (LOW, MEDIUM, HIGH)."""
        norm = risk_level.strip().upper()
        if norm not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk level '{risk_level}'. Must be LOW, MEDIUM, or HIGH.",
            )
        plan = engine.evaluate_risk_level("HIGH" if norm == "CRITICAL" else norm)
        return plan.to_dict()

    @app.get("/api/defense/checklist")
    def get_legacy_checklist(priority: Optional[str] = None, category: Optional[str] = None) -> dict[str, Any]:
        """Retrieve legacy checklist."""
        data = checklist.to_dict()
        items = data["checklist"]
        if priority:
            items = [i for i in items if i["priority"].upper() == priority.upper()]
        if category:
            items = [i for i in items if i["category"].upper() == category.upper()]
        data["checklist"] = items
        return data

    @app.get("/api/defense/auth-methods")
    def get_auth_methods() -> list[dict[str, Any]]:
        """Retrieve comparison matrix of authentication factors and their AiTM resistance."""
        return [p.to_dict() for p in kb.get_all_profiles()]

    @app.get("/api/defense/origin-binding")
    def get_origin_binding_explanation() -> dict[str, Any]:
        """Deep technical explanation of FIDO2 / WebAuthn origin-binding security invariants."""
        return kb.explain_origin_binding()

    @app.get("/api/defense/token-binding")
    def get_token_binding_explanation() -> dict[str, Any]:
        """Technical explanation of Cryptographic Token Binding (OAuth 2.0 DPoP / mTLS)."""
        return kb.explain_token_binding()


def run_standalone_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the API server with uvicorn (if installed)."""
    if not FASTAPI_AVAILABLE:
        print("FastAPI is not installed. Use Python functions directly.")
        return

    import uvicorn
    print(f"Starting Module 3 Defense & Hardening API at http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    init_db()
    run_standalone_server()
