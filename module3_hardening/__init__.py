"""
Module 3: FIDO2 / Passkey Defense & Hardening Engine
Owner: Vaishnavi (Branch: vaishnavi/hardening)

This module implements the defensive hardening engine, machine-readable checklists,
technical explanations of phishing-resistant authentication (FIDO2 / WebAuthn / Passkeys),
and risk-based automated recommendation playbooks that consume Module 2 detection outputs.
"""

from module3_hardening.models import (
    RiskLevel,
    AuthMethodType,
    AuthResistanceRating,
    AuthMethodProfile,
    ChecklistPriority,
    HardeningChecklistItem,
    DefenseRecommendation,
    HardeningPlan,
)
from module3_hardening.auth_defense import AuthDefenseKnowledgeBase
from module3_hardening.hardening_checklist import HardeningChecklist
from module3_hardening.recommendation_engine import HardeningEngine

__all__ = [
    "RiskLevel",
    "AuthMethodType",
    "AuthResistanceRating",
    "AuthMethodProfile",
    "ChecklistPriority",
    "HardeningChecklistItem",
    "DefenseRecommendation",
    "HardeningPlan",
    "AuthDefenseKnowledgeBase",
    "HardeningChecklist",
    "HardeningEngine",
]
