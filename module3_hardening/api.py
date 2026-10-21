"""
Defense & Hardening Engine REST API (Module 3).
Exposes endpoints for Module 4 (SOC Dashboard & User Training Frontend)
and other microservices to query defensive recommendations, hardening checklists,
and technical FIDO2/Passkey guidance.
"""

import sys
from typing import Any, Optional
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from fastapi import FastAPI, HTTPException, Body
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.hardening_checklist import HardeningChecklist
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase

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
        title="AiTM Defense & Hardening Engine API",
        description="Module 3: FIDO2 / Passkey Defense & Hardening Engine for AiTM Phishing Defense",
        version="1.0.0",
    )

    # Enable CORS for local React/Vite development (default Vite port 5173 / Next.js 3000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/defense/health")
    def health_check() -> dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "module": "Module 3: FIDO2/Passkey Defense & Hardening Engine",
            "owner": "Vaishnavi",
            "branch": "vaishnavi/hardening",
        }

    @app.get("/", response_class=HTMLResponse)
    def get_dashboard() -> HTMLResponse:
        """Serves the interactive SOC Detection & Hardening Web UI."""
        dashboard_path = Path(__file__).parent / "static" / "dashboard.html"
        if not dashboard_path.exists():
            return HTMLResponse("<h2>Dashboard HTML not found.</h2>", status_code=404)
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))

    @app.get("/api/events")
    def get_sample_events() -> list[dict[str, Any]]:
        """Returns synthetic authentication events from Module 1."""
        events_path = Path(__file__).resolve().parent.parent / "module1_aitm_poc" / "events" / "sample_events.json"
        if events_path.exists():
            with open(events_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

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
        """
        Consumes Module 2 detection output (risk_level, risk_score, signals, or composite detection result)
        and returns structured defense recommendations and SOC response playbooks.
        """
        try:
            plan = engine.evaluate_detection(payload)
            return plan.to_dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/defense/recommendations/{risk_level}")
    def get_recommendations_by_tier(risk_level: str) -> dict[str, Any]:
        """Quick endpoint to retrieve recommendations for a given tier (LOW, MEDIUM, HIGH)."""
        norm = risk_level.strip().upper()
        if norm not in ("LOW", "MEDIUM", "HIGH"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk level '{risk_level}'. Must be LOW, MEDIUM, or HIGH.",
            )
        plan = engine.evaluate_risk_level(norm)
        return plan.to_dict()

    @app.get("/api/defense/checklist")
    def get_checklist(priority: Optional[str] = None, category: Optional[str] = None) -> dict[str, Any]:
        """Retrieve the machine-readable hardening checklist."""
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
    run_standalone_server()
