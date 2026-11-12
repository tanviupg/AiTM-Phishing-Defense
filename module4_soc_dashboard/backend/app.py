"""
FastAPI Application for Module 4: SOC Dashboard & User-Training Module.

Exposes `/api/m4/*` endpoints backed by Modules 1, 2, and 3 (via
`ModuleIntegrationService`) and serves the modular frontend UI at `/`.
"""

from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from module4_soc_dashboard.backend.analytics_service import AnalyticsService
from module4_soc_dashboard.backend.integration_service import ModuleIntegrationService
from module4_soc_dashboard.backend.schemas import (
    ChecklistUpdateRequest,
    IncidentStatusUpdate,
    PipelineAnalyzeRequest,
    QuizQuestionCheckRequest,
    QuizSubmitRequest,
)
from module4_soc_dashboard.backend.training_service import TrainingService

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app(
    integration_service: Optional[ModuleIntegrationService] = None,
) -> FastAPI:
    """Application factory enabling isolated test injection."""
    integration = integration_service or ModuleIntegrationService()
    analytics = AnalyticsService(integration)
    training = TrainingService()

    app = FastAPI(
        title="AiTM Sentinel — Module 4 SOC Dashboard & User Training",
        description=(
            "Enterprise SOC monitoring console, threat analytics, incident triage, "
            "and interactive user phishing-awareness training integrated with Modules 1-3."
        ),
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="m4_static")

    @app.get("/", response_class=HTMLResponse)
    def serve_frontend() -> Any:
        index_path = FRONTEND_DIR / "index.html"
        if not index_path.exists():
            return HTMLResponse("<h2>Module 4 frontend not found.</h2>", status_code=404)
        return FileResponse(str(index_path), media_type="text/html")

    # ------------------------------------------------------------------
    # System & Provenance
    # ------------------------------------------------------------------

    @app.get("/api/m4/health")
    def health() -> dict[str, Any]:
        status = integration.get_system_status()
        return {
            "status": "healthy",
            "module": "Module 4: SOC Dashboard & User-Training Module",
            "integration_mode": status["integration_mode"],
            "is_mock_data": status["is_mock_data"],
        }

    @app.get("/api/m4/system/status")
    def system_status() -> dict[str, Any]:
        return integration.get_system_status()

    # ------------------------------------------------------------------
    # Overview, Threat Analysis & Charts
    # ------------------------------------------------------------------

    @app.get("/api/m4/dashboard/overview")
    def dashboard_overview() -> dict[str, Any]:
        return analytics.get_dashboard_overview()

    # ------------------------------------------------------------------
    # Security Event Monitoring & Pipeline Ingestion
    # ------------------------------------------------------------------

    @app.get("/api/m4/events")
    def list_events(
        severity: Optional[str] = None,
        incident_status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        return integration.get_events(
            severity=severity,
            incident_status=incident_status,
            search=search,
            limit=limit,
        )

    @app.post("/api/m4/pipeline/ingest-module1")
    def ingest_module1() -> dict[str, Any]:
        return integration.ingest_module1_samples()

    @app.post("/api/m4/pipeline/analyze")
    def analyze_synthetic_event(payload: PipelineAnalyzeRequest) -> dict[str, Any]:
        try:
            event_dict = (
                payload.model_dump(exclude_none=True)
                if hasattr(payload, "model_dump")
                else payload.dict(exclude_none=True)
            )
            return integration.analyze_and_ingest_event(event_dict, persist=True)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
        except RuntimeError as err:
            raise HTTPException(status_code=503, detail=str(err))

    # ------------------------------------------------------------------
    # Module 3 Controlled Lab Scenarios
    # ------------------------------------------------------------------

    @app.get("/api/m4/lab/scenarios")
    def lab_scenarios() -> list[dict[str, Any]]:
        return integration.get_lab_scenarios()

    @app.post("/api/m4/lab/scenarios/{scenario_id}/run")
    def run_scenario(scenario_id: str) -> dict[str, Any]:
        try:
            return integration.run_lab_scenario(scenario_id)
        except ValueError as err:
            raise HTTPException(status_code=404, detail=str(err))
        except Exception as err:
            raise HTTPException(status_code=500, detail=f"Scenario error: {err}")

    @app.post("/api/m4/lab/reset")
    def reset_lab() -> dict[str, Any]:
        return integration.reset_lab_data()

    # ------------------------------------------------------------------
    # Incident Management
    # ------------------------------------------------------------------

    @app.get("/api/m4/incidents")
    def list_incidents(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict[str, Any]:
        return integration.get_incidents(severity=severity, status=status, search=search)

    @app.get("/api/m4/incidents/{incident_id}")
    def incident_details(incident_id: str) -> dict[str, Any]:
        details = integration.get_incident_details(incident_id)
        if not details:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        return details

    @app.patch("/api/m4/incidents/{incident_id}/status")
    def update_incident_status(incident_id: str, payload: IncidentStatusUpdate) -> dict[str, Any]:
        updated = integration.update_incident_status(incident_id, payload.status)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        return updated

    # ------------------------------------------------------------------
    # Sessions & Containment (Module 3 Integration)
    # ------------------------------------------------------------------

    @app.get("/api/m4/sessions")
    def list_sessions() -> dict[str, Any]:
        return integration.get_sessions()

    @app.post("/api/m4/sessions/{session_id}/revoke")
    def revoke_session(session_id: str) -> dict[str, Any]:
        return integration.revoke_session(session_id, performed_by="Module4-SOC-Analyst")

    @app.post("/api/m4/sessions/{session_id}/test_access")
    def test_session_access(session_id: str) -> dict[str, Any]:
        return integration.test_session_access(session_id)

    # ------------------------------------------------------------------
    # FIDO2 / Passkey Defense & Hardening (Module 3 Integration)
    # ------------------------------------------------------------------

    @app.get("/api/m4/hardening/overview")
    def hardening_overview() -> dict[str, Any]:
        return integration.get_hardening_overview()

    @app.patch("/api/m4/hardening/checklist/{item_id}")
    def update_checklist(item_id: str, payload: ChecklistUpdateRequest) -> dict[str, Any]:
        updated = integration.update_checklist_item(item_id, payload.status, payload.notes)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Checklist item '{item_id}' not found.")
        return updated

    # ------------------------------------------------------------------
    # User-Training Module & Interactive Quiz
    # ------------------------------------------------------------------

    @app.get("/api/m4/training/lessons")
    def training_lessons() -> dict[str, Any]:
        lessons = training.get_lessons()
        return {
            "total_lessons": len(lessons),
            "lessons": lessons,
        }

    @app.get("/api/m4/training/quiz")
    def training_quiz() -> dict[str, Any]:
        questions = training.get_quiz_questions()
        return {
            "title": "AiTM Phishing Defense & Passkey Awareness Assessment",
            "total_questions": len(questions),
            "passing_threshold_pct": training.PASSING_THRESHOLD_PCT,
            "questions": questions,
        }

    @app.post("/api/m4/training/quiz/check")
    def check_quiz_question(payload: QuizQuestionCheckRequest) -> dict[str, Any]:
        try:
            return training.check_single_question(payload.question_id, payload.selected_index)
        except ValueError as err:
            raise HTTPException(status_code=404, detail=str(err))

    @app.post("/api/m4/training/quiz/submit")
    def submit_quiz(payload: QuizSubmitRequest) -> dict[str, Any]:
        return training.grade_quiz(payload.answers)

    return app


app = create_app()
