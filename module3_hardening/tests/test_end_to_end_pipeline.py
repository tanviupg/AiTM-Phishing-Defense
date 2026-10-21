"""
Integration tests for the complete AiTM defense pipeline:
Module 1 (Event Gen) -> Module 2 (Detection) -> Module 3 (Hardening & Recommendations).
"""

import json
from pathlib import Path
import unittest

from module1_aitm_poc.event_generator import validate_event
from module2_detection.detector import AiTMDetector
from module2_detection.session_tracker import SessionTracker
from module2_detection.tls_analyzer import TLSAnalyzer
from module3_hardening.recommendation_engine import HardeningEngine
from module3_hardening.models import RiskLevel
from module3_hardening.api import (
    get_recommendations_for_event,
    get_hardening_checklist_data,
    get_auth_methods_matrix,
)


class TestEndToEndPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = AiTMDetector()
        self.session_tracker = SessionTracker()
        self.tls_analyzer = TLSAnalyzer()
        self.engine = HardeningEngine()

    def test_benign_event_full_pipeline_flow(self) -> None:
        """Module 1 normal event -> Module 2 benign detection -> Module 3 LOW tier defense."""
        benign_event = {
            "session_id": "LAB-001",
            "timestamp": "2026-10-21T12:00:00Z",
            "auth_result": "success",
            "redirect_count": 1,
            "redirect_chain": ["lab-idp.local"],
            "tls_anomaly": False,
            "replay_indicator": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEVICE-A",
            "scenario": "normal",
        }
        self.assertTrue(validate_event(benign_event))

        # Module 2
        det_result = self.detector.analyze_event_composite(
            benign_event,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
        )
        self.assertEqual(det_result["composite_verdict"], "benign")
        self.assertLess(det_result["composite_risk_score"], 0.30)

        # Module 3
        plan = self.engine.evaluate_detection(det_result)
        self.assertEqual(plan.input_risk_level, RiskLevel.LOW)
        self.assertIn("Continue monitoring", plan.primary_recommendations)

    def test_suspicious_event_full_pipeline_flow(self) -> None:
        """Module 1 suspicious event -> Module 2 suspicious detection -> Module 3 HIGH tier defense."""
        suspicious_event = {
            "session_id": "LAB-002",
            "timestamp": "2026-10-21T12:05:00Z",
            "auth_result": "success",
            "redirect_count": 4,
            "redirect_chain": [
                "lab-login.local",
                "proxy-simulation.local",
                "lab-idp.local",
                "lab-login.local",
            ],
            "tls_anomaly": True,
            "replay_indicator": True,
            "source_ip": "198.51.100.20",
            "device_id": "DEVICE-B",
            "scenario": "suspicious_simulation",
        }
        self.assertTrue(validate_event(suspicious_event))

        # Module 2
        det_result = self.detector.analyze_event_composite(
            suspicious_event,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
        )
        self.assertEqual(det_result["composite_verdict"], "suspicious")
        self.assertGreaterEqual(det_result["composite_risk_score"], 0.50)

        # Module 3
        plan = self.engine.evaluate_detection(det_result)
        self.assertEqual(plan.input_risk_level, RiskLevel.HIGH)
        self.assertIn("Investigate session", plan.primary_recommendations)
        self.assertIn("Re-authenticate user", plan.primary_recommendations)
        self.assertIn("Prefer FIDO2/passkey", plan.primary_recommendations)

    def test_api_helpers_produce_valid_data(self) -> None:
        checklist_data = get_hardening_checklist_data()
        self.assertIn("recommendations", checklist_data)
        self.assertIn("checklist", checklist_data)

        methods = get_auth_methods_matrix()
        self.assertIsInstance(methods, list)
        self.assertGreaterEqual(len(methods), 5)

        sample_detection = {
            "session_id": "API-TEST",
            "risk_score": 0.85,
            "risk_level": "HIGH",
            "signals": {"tls_anomaly": True},
        }
        rec_data = get_recommendations_for_event(sample_detection)
        self.assertEqual(rec_data["risk_level"], "HIGH")
        self.assertIn("recommendations", rec_data)


if __name__ == "__main__":
    unittest.main()
