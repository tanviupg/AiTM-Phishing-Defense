import unittest
import sys
from datetime import datetime, timezone
from pathlib import Path

MODULE2_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE2_DIR))

from detector import AiTMDetector, DetectionResult, CompositeDetectionResult
from session_tracker import SessionTracker
from tls_analyzer import TLSAnalyzer


class TestCompositeDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AiTMDetector()
        self.session_tracker = SessionTracker()
        self.tls_analyzer = TLSAnalyzer()
        self.ref_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_composite_preserves_base_analyze_event_contract(self):
        # Base analyze_event must remain 100% identical in output structure and score
        event = {
            "session_id": "BASE-CHECK-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
        }
        res = self.detector.analyze_event(event)

        self.assertEqual(res["session_id"], "BASE-CHECK-01")
        self.assertEqual(res["verdict"], "benign")
        self.assertEqual(res["risk_score"], 0.0)
        self.assertEqual(res["triggered_rules"], [])

    def test_composite_with_no_optional_telemetry(self):
        # When optional components are omitted, composite score equals base score
        event = {
            "session_id": "COMP-NOOPT-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
        }
        comp_res = self.detector.analyze_event_composite(event)

        self.assertEqual(comp_res["composite_verdict"], "benign")
        self.assertEqual(comp_res["composite_risk_score"], 0.0)
        self.assertIsNone(comp_res["session_correlation"])
        self.assertIsNone(comp_res["tls_analysis"])

    def test_composite_catches_session_replay_even_when_base_is_clean(self):
        ev1 = {
            "session_id": "COMP-REPLAY-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        }
        ev2 = {
            "session_id": "COMP-REPLAY-01",
            "timestamp": "2026-10-15T12:00:15Z",
            "redirect_count": 3,
            "redirect_chain": ["app.example.com", "idp.example.com", "app.example.com"],
            "tls_anomaly": False,
            "source_ip": "198.51.100.99",
            "device_id": "DEV-ATTACKER-99",
        }

        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(
            ev2,
            session_tracker=self.session_tracker,
            reference_time=self.ref_time,
        )

        self.assertIsNotNone(res2["session_correlation"])
        self.assertIn("session:SUSPICIOUS_CONTEXT_MISMATCH", res2["all_triggered_indicators"])
        self.assertIn("SUSPICIOUS_CONTEXT_MISMATCH", res2["indicators_by_source"]["session"])
        self.assertGreaterEqual(res2["composite_risk_score"], 0.30)
        self.assertIn("simultaneous device mismatch", res2["composite_explanation"])

    def test_composite_catches_hostname_mismatch_with_clean_redirect(self):
        event = {
            "session_id": "COMP-MISMATCH-01",
            "redirect_count": 1,
            "redirect_chain": ["login.company.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "attacker-proxy.net",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }

        res = self.detector.analyze_event_composite(
            event,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )

        self.assertIn("tls:CERT_HOSTNAME_MISMATCH", res["all_triggered_indicators"])
        self.assertIn("CERT_HOSTNAME_MISMATCH", res["indicators_by_source"]["tls"])
        self.assertGreaterEqual(res["composite_risk_score"], 0.30)

    def test_composite_missing_telemetry_does_not_alert(self):
        event = {
            "session_id": "COMP-MISSING-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
        }

        res = self.detector.analyze_event_composite(
            event,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
        )

        self.assertEqual(res["composite_verdict"], "benign")
        self.assertEqual(res["composite_risk_score"], 0.0)
        self.assertIn("session:MISSING_TELEMETRY", res["all_triggered_indicators"])
        self.assertIn("tls:UNOBSERVED_TLS_TELEMETRY", res["all_triggered_indicators"])

    def test_composite_zero_leakage(self):
        base_event = {
            "session_id": "COMP-SHORTCUT-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
        }

        ev_a = dict(base_event, scenario="normal", replay_indicator=False, ground_truth="benign")
        ev_b = dict(base_event, scenario="suspicious_simulation", replay_indicator=True, ground_truth="suspicious")

        res_a = self.detector.analyze_event_composite(ev_a)
        res_b = self.detector.analyze_event_composite(ev_b)

        self.assertEqual(res_a["composite_verdict"], res_b["composite_verdict"])
        self.assertEqual(res_a["composite_risk_score"], res_b["composite_risk_score"])
        self.assertEqual(res_a["all_triggered_indicators"], res_b["all_triggered_indicators"])


if __name__ == "__main__":
    unittest.main()
