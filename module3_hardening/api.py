"""
Defense & Hardening Engine REST API (Module 3).
Exposes endpoints for Module 4 (SOC Dashboard & User Training Frontend)
and other microservices to query defensive recommendations, hardening checklists,
and technical FIDO2/Passkey guidance.
"""

from typing import Any, Optional
import json

try:
    from fastapi import FastAPI, HTTPException, Body
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.hardening_checklist import HardeningChecklist
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase

engine = HardeningEngine()
checklist = HardeningChecklist()
kb = AuthDefenseKnowledgeBase()


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
