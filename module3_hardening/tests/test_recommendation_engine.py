"""
Unit tests for Module 3: Defensive Recommendation Engine.
Tests risk level mappings (LOW, MEDIUM, HIGH), signal-driven actions,
and input format normalization.
"""

import unittest
from module3_hardening.models import RiskLevel, HardeningPlan
from module3_hardening.recommendation_engine import HardeningEngine


class TestRecommendationEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = HardeningEngine()

    def test_low_risk_evaluation(self) -> None:
        payload = {
            "session_id": "TEST-LOW-01",
            "risk_score": 0.10,
            "risk_level": "LOW",
            "signals": {
                "tls_anomaly": False,
                "redirect_anomaly": False,
                "replay_indicator": False,
            },
        }
        plan = self.engine.evaluate_detection(payload)
        self.assertEqual(plan.input_risk_level, RiskLevel.LOW)
        self.assertEqual(plan.risk_score_percent, 10)
        self.assertIn("Continue monitoring", plan.primary_recommendations)
        self.assertTrue(any("monitoring" in b.lower() for b in [plan.summary_banner]))

    def test_medium_risk_evaluation(self) -> None:
        payload = {
            "session_id": "TEST-MED-01",
            "risk_score": 0.40,
            "risk_level": "MEDIUM",
            "signals": {
                "tls_anomaly": True,
                "redirect_anomaly": False,
                "replay_indicator": False,
            },
        }
        plan = self.engine.evaluate_detection(payload)
        self.assertEqual(plan.input_risk_level, RiskLevel.MEDIUM)
        self.assertEqual(plan.risk_score_percent, 40)
        self.assertIn("Investigate authentication activity", plan.primary_recommendations)
        self.assertTrue(any("TLS Certificate Anomaly" in r for r in plan.signal_specific_remediations))

    def test_high_risk_evaluation_matches_specification(self) -> None:
        payload = {
            "session_id": "LAB-001",
            "risk_score": 85,
            "risk_level": "HIGH",
            "signals": {
                "tls_anomaly": True,
                "redirect_anomaly": True,
                "replay_indicator": False,
            },
        }
        plan = self.engine.evaluate_detection(payload)
        self.assertEqual(plan.input_risk_level, RiskLevel.HIGH)
        self.assertEqual(plan.risk_score_percent, 85)

        # Check required recommendations from problem statement:
        # HIGH -> Investigate session, Re-authenticate user, Prefer FIDO2/passkey
        self.assertIn("Investigate session", plan.primary_recommendations)
        self.assertIn("Re-authenticate user", plan.primary_recommendations)
        self.assertIn("Prefer FIDO2/passkey", plan.primary_recommendations)

        # Verify automated remediation items
        action_titles = [a.title for a in plan.detailed_actions]
        self.assertTrue(any("Session Invalidation" in t for t in action_titles))
        self.assertTrue(any("Phishing-Resistant" in t for t in action_titles))

    def test_composite_detection_result_dict_input(self) -> None:
        """Verify seamless consumption of Module 2 CompositeDetectionResult dictionary."""
        composite_result = {
            "session_id": "V2-SUSP-01",
            "composite_verdict": "suspicious",
            "composite_risk_score": 0.90,
            "all_triggered_indicators": [
                "base:SUSPICIOUS_REDIRECT_CYCLE",
                "base:EXCESSIVE_REDIRECT_COUNT",
                "tls:LEGACY_TLS_ANOMALY_FLAG",
                "session:TOKEN_BINDING_FAILURE",
            ],
            "composite_explanation": "cyclic redirect loop detected; token binding failure",
        }
        plan = self.engine.evaluate_detection(composite_result)
        self.assertEqual(plan.input_risk_level, RiskLevel.HIGH)
        self.assertEqual(plan.risk_score_percent, 90)
        self.assertIn("Investigate session", plan.primary_recommendations)
        self.assertTrue(any("Token Binding" in r for r in plan.signal_specific_remediations))

    def test_serialization_to_dict(self) -> None:
        plan = self.engine.evaluate_risk_level("HIGH", session_id="TEST-SER")
        d = plan.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["session_id"], "TEST-SER")
        self.assertEqual(d["risk_level"], "HIGH")
        self.assertIn("recommendations", d)
        self.assertIn("detailed_actions", d)
        self.assertIn("phishing_resistant_strategy", d)

    def test_resilience_to_missing_fields(self) -> None:
        """Handles sparse dictionaries safely without raising exceptions."""
        sparse_input = {"session_id": "SPARSE-01"}
        plan = self.engine.evaluate_detection(sparse_input)
        self.assertEqual(plan.session_id, "SPARSE-01")
        self.assertEqual(plan.input_risk_level, RiskLevel.LOW)
        self.assertEqual(plan.risk_score_percent, 0)


if __name__ == "__main__":
    unittest.main()
