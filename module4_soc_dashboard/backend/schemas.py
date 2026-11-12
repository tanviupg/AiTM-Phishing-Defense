"""
Pydantic request/response schemas and constants for Module 4 SOC Dashboard.
"""

from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

ALLOWED_INCIDENT_STATUSES = ("Open", "Investigating", "Contained", "Resolved")


class IncidentStatusUpdate(BaseModel):
    """Payload to update an incident triage status."""
    status: Literal["Open", "Investigating", "Contained", "Resolved"]
    analyst: Optional[str] = Field(default="Josna (SOC Analyst)", max_length=100)


class QuizQuestionCheckRequest(BaseModel):
    """Payload to check a single quiz question with immediate feedback."""
    question_id: str
    selected_index: int = Field(ge=0, le=3)


class QuizSubmitRequest(BaseModel):
    """Payload to grade the complete phishing-awareness quiz."""
    answers: dict[str, int]


class ChecklistUpdateRequest(BaseModel):
    """Payload to update a Module 3 hardening checklist item."""
    status: Literal["Not assessed", "In progress", "Verified", "Not applicable"]
    notes: Optional[str] = None


class PipelineAnalyzeRequest(BaseModel):
    """Synthetic event payload conforming to integration/event_schema.json."""
    session_id: str
    timestamp: Optional[str] = None
    auth_result: str = "success"
    redirect_count: int = Field(ge=0, default=1)
    redirect_chain: list[str]
    tls_anomaly: bool = False
    replay_indicator: bool = False
    source_ip: str = "192.0.2.10"
    device_id: str = "DEVICE-LAB-01"
    scenario: str = "normal"
    user_alias: Optional[str] = "alice@lab.local"
    token_binding_status: Optional[str] = None
    client_platform: Optional[str] = None
    certificate_telemetry: Optional[dict[str, Any]] = None
