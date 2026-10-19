import unittest
import sys
from pathlib import Path

# Add module2_detection parent to path so detector can be imported cleanly
MODULE2_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE2_DIR))

from detector import AiTMDetector, DetectionResult


class TestAiTMDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AiTMDetector()

    # ---------------------------------------------------------
    # 1. Normal Events
    # ---------------------------------------------------------
    def test_normal_single_redirect_event(self):
        event = {
            "session_id": "LAB-001",
            "redirect_count": 1,
            "redirect_chain": ["lab-idp.local"],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["session_id"], "LAB-001")
        self.assertEqual(result["verdict"], "benign")
        self.assertLess(result["risk_score"], 0.50)
        self.assertEqual(result["triggered_rules"], [])
        self.assertIn("no suspicious redirect or transport patterns detected", result["explanation"])

    def test_normal_direct_login_no_redirect(self):
        event = {
            "session_id": "LAB-DIRECT",
            "redirect_count": 0,
            "redirect_chain": ["portal.internal"],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "benign")
        self.assertEqual(result["risk_score"], 0.0)
        self.assertEqual(result["triggered_rules"], [])

    # ---------------------------------------------------------
    # 2. Suspicious AiTM Redirect Patterns
    # ---------------------------------------------------------
    def test_suspicious_aitm_proxy_sandwich_with_tls_anomaly(self):
        # Mirroring LAB-002 proxy simulation pattern
        event = {
            "session_id": "LAB-002",
            "redirect_count": 4,
            "redirect_chain": [
                "lab-login.local",
                "proxy-simulation.local",
                "lab-idp.local",
                "lab-login.local",
            ],
            "tls_anomaly": True,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["session_id"], "LAB-002")
        self.assertEqual(result["verdict"], "suspicious")
        self.assertGreaterEqual(result["risk_score"], 0.50)
        self.assertIn("SUSPICIOUS_REDIRECT_CYCLE", result["triggered_rules"])
        self.assertIn("EXCESSIVE_REDIRECT_COUNT", result["triggered_rules"])
        self.assertIn("TLS_ANOMALY", result["triggered_rules"])

    def test_suspicious_proxy_insertion_without_tls_anomaly(self):
        # Even without TLS anomaly, proxy intermediary cycle and excessive hops trigger suspicion
        event = {
            "session_id": "LAB-STEALTH-PROXY",
            "redirect_count": 4,
            "redirect_chain": [
                "login.target.com",
                "evil-aitm-proxy.net",
                "idp.target.com",
                "login.target.com",
            ],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "suspicious")
        self.assertIn("SUSPICIOUS_REDIRECT_CYCLE", result["triggered_rules"])
        self.assertIn("EXCESSIVE_REDIRECT_COUNT", result["triggered_rules"])
        self.assertNotIn("TLS_ANOMALY", result["triggered_rules"])
        self.assertGreaterEqual(result["risk_score"], 0.50)

    def test_suspicious_excessive_redirect_chain(self):
        event = {
            "session_id": "LAB-HOPPER",
            "redirect_count": 6,
            "redirect_chain": ["a.com", "b.com", "c.com", "d.com", "e.com"],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "suspicious")
        self.assertIn("EXCESSIVE_REDIRECT_COUNT", result["triggered_rules"])
        self.assertIn("HIGH_TRANSITION_COMPLEXITY", result["triggered_rules"])

    # ---------------------------------------------------------
    # 3. Legitimate Redirect Edge Cases (False Positive Defense)
    # ---------------------------------------------------------
    def test_legitimate_federated_sso_bounce_pattern(self):
        # Canonical SAML/OIDC flow: SP -> IdP -> SP
        event = {
            "session_id": "LAB-LEGIT-SSO",
            "redirect_count": 2,
            "redirect_chain": [
                "app.corp.local",
                "login.microsoftonline.com",
                "app.corp.local",
            ],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "benign")
        self.assertNotIn("REPEATED_REDIRECT_HOST", result["triggered_rules"])
        self.assertNotIn("SUSPICIOUS_REDIRECT_CYCLE", result["triggered_rules"])
        self.assertLess(result["risk_score"], 0.50)

    def test_legitimate_sso_with_slight_redirect_variance(self):
        # Canonical SSO bounce with redirect_count 3
        event = {
            "session_id": "LAB-SSO-COUNT3",
            "redirect_count": 3,
            "redirect_chain": [
                "jira.internal.net",
                "okta.internal.net",
                "jira.internal.net",
            ],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "benign")
        self.assertNotIn("SUSPICIOUS_REDIRECT_CYCLE", result["triggered_rules"])
        self.assertLess(result["risk_score"], 0.50)

    def test_benign_subdomain_transition(self):
        event = {
            "session_id": "LAB-SUBDOMAIN",
            "redirect_count": 1,
            "redirect_chain": ["service.example.org", "auth.example.org"],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertEqual(result["verdict"], "benign")
        self.assertEqual(result["risk_score"], 0.0)

    # ---------------------------------------------------------
    # 4. Telemetry Inconsistency Detection
    # ---------------------------------------------------------
    def test_telemetry_divergence_warning(self):
        # Reported redirect_count is 0, but chain length is 3 (hidden/dropped hops)
        event = {
            "session_id": "LAB-DIVERGENT",
            "redirect_count": 0,
            "redirect_chain": ["entry.com", "step2.com", "final.com"],
            "tls_anomaly": False,
        }
        result = self.detector.analyze_event(event)

        self.assertIn("REDIRECT_TELEMETRY_DIVERGENCE", result["triggered_rules"])

    # ---------------------------------------------------------
    # 5. Strict Zero-Shortcut Verification
    # ---------------------------------------------------------
    def test_detector_does_not_leak_or_use_scenario_or_replay_indicator(self):
        base_event = {
            "session_id": "LAB-SHORTCUT-CHECK",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
        }

        # Case A: with normal labels
        event_a = dict(base_event)
        event_a["scenario"] = "normal"
        event_a["replay_indicator"] = False

        # Case B: with suspicious simulation labels & replay indicator set to True
        event_b = dict(base_event)
        event_b["scenario"] = "suspicious_simulation"
        event_b["replay_indicator"] = True

        result_a = self.detector.analyze_event(event_a)
        result_b = self.detector.analyze_event(event_b)

        # Output MUST be completely identical regardless of scenario or replay_indicator
        self.assertEqual(result_a["verdict"], result_b["verdict"])
        self.assertEqual(result_a["risk_score"], result_b["risk_score"])
        self.assertEqual(result_a["triggered_rules"], result_b["triggered_rules"])
        self.assertEqual(result_a["explanation"], result_b["explanation"])

    # ---------------------------------------------------------
    # 6. Malformed and Invalid Inputs
    # ---------------------------------------------------------
    def test_rejects_non_dictionary_event(self):
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(["not", "a", "dict"])
        self.assertIn("must be a dictionary", str(ctx.exception))

    def test_rejects_missing_required_fields(self):
        incomplete_event = {"session_id": "LAB-BAD"}
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(incomplete_event)
        self.assertIn("Missing required fields", str(ctx.exception))

    def test_rejects_invalid_session_id_type(self):
        bad_event = {
            "session_id": 12345,
            "redirect_count": 1,
            "redirect_chain": ["auth.host"],
            "tls_anomaly": False,
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("session_id must be a string", str(ctx.exception))

    def test_rejects_negative_redirect_count(self):
        bad_event = {
            "session_id": "LAB-NEG",
            "redirect_count": -1,
            "redirect_chain": ["auth.host"],
            "tls_anomaly": False,
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("non-negative integer", str(ctx.exception))

    def test_rejects_boolean_redirect_count(self):
        # Python bool inherits from int, detector must reject True/False
        bad_event = {
            "session_id": "LAB-BOOL-COUNT",
            "redirect_count": True,
            "redirect_chain": ["auth.host"],
            "tls_anomaly": False,
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("non-negative integer", str(ctx.exception))

    def test_rejects_non_list_redirect_chain(self):
        bad_event = {
            "session_id": "LAB-STR-CHAIN",
            "redirect_count": 1,
            "redirect_chain": "auth.host.only",
            "tls_anomaly": False,
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("must be a list of strings", str(ctx.exception))

    def test_rejects_non_string_host_in_redirect_chain(self):
        bad_event = {
            "session_id": "LAB-NON-STR-HOST",
            "redirect_count": 1,
            "redirect_chain": ["good.host", 999],
            "tls_anomaly": False,
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("must be a list of strings", str(ctx.exception))

    def test_rejects_non_boolean_tls_anomaly(self):
        bad_event = {
            "session_id": "LAB-BAD-TLS",
            "redirect_count": 1,
            "redirect_chain": ["auth.host"],
            "tls_anomaly": "false",  # String instead of bool
        }
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_event(bad_event)
        self.assertIn("tls_anomaly must be a boolean", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
