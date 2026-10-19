import json
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

    def test_composite_risk_score_capping_at_one(self):
        # Base event triggers SUSPICIOUS_REDIRECT_CYCLE (0.35) + EXCESSIVE_REDIRECT_COUNT (0.30) + TLS_ANOMALY (0.25) = 0.90
        # Coupled with CERT_HOSTNAME_MISMATCH (+0.30) and SUSPICIOUS_CONTEXT_MISMATCH (+0.30)
        # Sum = 0.90 + 0.30 + 0.30 = 1.50 -> must cap at exactly 1.00
        ev1 = {
            "session_id": "COMP-CAP-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["login.company.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)

        ev2 = {
            "session_id": "COMP-CAP-01",
            "timestamp": "2026-10-15T12:00:15Z",
            "redirect_count": 4,
            "redirect_chain": ["login.company.com", "evil-proxy.com", "idp.company.com", "login.company.com"],
            "tls_anomaly": True,
            "source_ip": "198.51.100.99",
            "device_id": "DEV-ATTACKER-99",
            "certificate_telemetry": {
                "subject_cn": "untrusted-mitm.net",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }

        res = self.detector.analyze_event_composite(
            ev2,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )

        self.assertEqual(res["composite_risk_score"], 1.0)
        self.assertEqual(res["composite_verdict"], "suspicious")

    def test_verdict_threshold_exact_boundary(self):
        # Case A: Below threshold (isolated CERT_HOSTNAME_MISMATCH at 0.30)
        ev_below = {
            "session_id": "COMP-THRESH-BELOW",
            "redirect_count": 1,
            "redirect_chain": ["login.target.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "mismatch-proxy.org",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }
        res_below = self.detector.analyze_event_composite(
            ev_below,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res_below["composite_risk_score"], 0.30)
        self.assertEqual(res_below["composite_verdict"], "benign")

        # Case B: Exactly at threshold 0.50 (Base 0.35 + TLS SNI_HOST_MISMATCH 0.15 = 0.50)
        # Base: HIGH_TRANSITION_COMPLEXITY (0.20) + ELEVATED_REDIRECT_COUNT (0.15) = 0.35
        ev_exact = {
            "session_id": "COMP-THRESH-EXACT",
            "redirect_count": 3,
            "redirect_chain": ["a.com", "b.com", "c.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "a.com",
                "sni_hostname": "different-host.com",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }
        res_exact = self.detector.analyze_event_composite(
            ev_exact,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res_exact["composite_risk_score"], 0.50)
        self.assertEqual(res_exact["composite_verdict"], "suspicious")

    def test_composite_result_field_structure_and_namespacing(self):
        ev1 = {
            "session_id": "COMP-STRUCT-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)

        ev2 = {
            "session_id": "COMP-STRUCT-01",
            "timestamp": "2026-10-15T12:00:20Z",
            "redirect_count": 4,
            "redirect_chain": ["login.target.com", "proxy.target.com", "idp.target.com", "login.target.com"],
            "tls_anomaly": True,
            "source_ip": "198.51.100.20",
            "device_id": "DEV-02",
            "certificate_telemetry": {
                "subject_cn": "evil-cert.com",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }
        res = self.detector.analyze_event_composite(
            ev2,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )

        # 1. Assert top-level keys
        expected_keys = {
            "session_id",
            "base_detection",
            "session_correlation",
            "tls_analysis",
            "composite_verdict",
            "composite_risk_score",
            "all_triggered_indicators",
            "composite_explanation",
            "indicators_by_source",
        }
        self.assertEqual(set(res.keys()), expected_keys)

        # 2. Assert sub-dictionary keys
        self.assertEqual(
            set(res["base_detection"].keys()),
            {"session_id", "verdict", "risk_score", "triggered_rules", "explanation"},
        )
        self.assertIsNotNone(res["session_correlation"])
        self.assertEqual(
            set(res["session_correlation"].keys()),
            {"session_id", "is_correlated", "event_count", "delta_seconds", "indicators", "explanation", "context_details"},
        )
        self.assertIsNotNone(res["tls_analysis"])
        self.assertEqual(
            set(res["tls_analysis"].keys()),
            {"is_anomaly", "indicators", "confidence", "explanation", "legitimate_causes", "details"},
        )

        # 3. Assert namespacing integrity in all_triggered_indicators
        self.assertTrue(len(res["all_triggered_indicators"]) > 0)
        for indicator in res["all_triggered_indicators"]:
            self.assertTrue(
                indicator.startswith("base:") or indicator.startswith("tls:") or indicator.startswith("session:"),
                f"Indicator '{indicator}' is not properly namespaced",
            )

        # 4. Assert indicators_by_source grouping
        self.assertEqual(set(res["indicators_by_source"].keys()), {"base", "tls", "session"})
        for base_rule in res["indicators_by_source"]["base"]:
            self.assertIn(f"base:{base_rule}", res["all_triggered_indicators"])
        for tls_ind in res["indicators_by_source"]["tls"]:
            self.assertIn(f"tls:{tls_ind}", res["all_triggered_indicators"])
        for sess_ind in res["indicators_by_source"]["session"]:
            self.assertIn(f"session:{sess_ind}", res["all_triggered_indicators"])

    def test_composite_result_json_serialization(self):
        ev = {
            "session_id": "COMP-JSON-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 2,
            "redirect_chain": ["app.example.com", "login.microsoftonline.com", "app.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "certificate_telemetry": {
                "subject_cn": "login.microsoftonline.com",
                "issuer_org": "DigiCert Inc",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "is_self_signed": False,
            },
        }
        res = self.detector.analyze_event_composite(
            ev,
            session_tracker=self.session_tracker,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )

        # Must serialize cleanly to JSON string without TypeError or datetime serialization errors
        serialized = json.dumps(res, indent=2)
        deserialized = json.loads(serialized)

        self.assertEqual(deserialized["session_id"], "COMP-JSON-01")
        self.assertEqual(deserialized["composite_verdict"], res["composite_verdict"])
        self.assertEqual(deserialized["composite_risk_score"], res["composite_risk_score"])
        self.assertEqual(deserialized["all_triggered_indicators"], res["all_triggered_indicators"])
        self.assertEqual(deserialized["indicators_by_source"], res["indicators_by_source"])


    # -------------------------------------------------------------
    # Independent Composite Modifiers
    # -------------------------------------------------------------
    def test_modifier_untrusted_self_signed_cert_independent_score(self):
        # Base event is clean (score 0.0)
        # Adding untrusted self-signed cert should yield composite score exactly 0.20
        event = {
            "session_id": "MOD-SELFSIGN-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "is_self_signed": True,
                "validation_status": "untrusted_root",
            },
        }
        res = self.detector.analyze_event_composite(
            event,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res["composite_risk_score"], 0.20)
        self.assertEqual(res["composite_verdict"], "benign")
        self.assertIn("tls:UNTRUSTED_SELF_SIGNED_CERT", res["all_triggered_indicators"])
        self.assertEqual(res["indicators_by_source"]["base"], [])

    def test_modifier_cert_expired_and_not_yet_valid_independent_score(self):
        # Expired cert: base 0.0 + modifier 0.15 = 0.15
        ev_exp = {
            "session_id": "MOD-EXPIRED-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2025-12-31T23:59:59Z",
            },
        }
        res_exp = self.detector.analyze_event_composite(
            ev_exp,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res_exp["composite_risk_score"], 0.15)
        self.assertEqual(res_exp["composite_verdict"], "benign")
        self.assertIn("tls:CERT_EXPIRED", res_exp["all_triggered_indicators"])

        # Not yet valid cert: base 0.0 + modifier 0.15 = 0.15
        ev_future = {
            "session_id": "MOD-FUTURE-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "2027-01-01T00:00:00Z",
                "not_after": "2027-12-31T23:59:59Z",
            },
        }
        res_future = self.detector.analyze_event_composite(
            ev_future,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res_future["composite_risk_score"], 0.15)
        self.assertEqual(res_future["composite_verdict"], "benign")
        self.assertIn("tls:CERT_NOT_YET_VALID", res_future["all_triggered_indicators"])

    def test_modifier_sni_host_mismatch_independent_score(self):
        # SNI mismatch: base 0.0 + modifier 0.15 = 0.15
        event = {
            "session_id": "MOD-SNI-01",
            "redirect_count": 1,
            "redirect_chain": ["login.company.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "login.company.com",
                "sni_hostname": "different-gateway.net",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }
        res = self.detector.analyze_event_composite(
            event,
            tls_analyzer=self.tls_analyzer,
            reference_time=self.ref_time,
        )
        self.assertEqual(res["composite_risk_score"], 0.15)
        self.assertEqual(res["composite_verdict"], "benign")
        self.assertIn("tls:SNI_HOST_MISMATCH", res["all_triggered_indicators"])

    def test_modifier_device_context_changed_independent_score(self):
        # Device changed, but IP constant (e.g. same corporate egress IP, delta > rapid window)
        # Yields DEVICE_CONTEXT_CHANGED (+0.15) without RAPID_SOURCE_IP_CHANGE or SUSPICIOUS_CONTEXT_MISMATCH
        ev1 = {
            "session_id": "MOD-DEV-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-LAPTOP-01",
        }
        ev2 = {
            "session_id": "MOD-DEV-01",
            "timestamp": "2026-10-15T12:05:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-PHONE-02",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(ev2, session_tracker=self.session_tracker)

        self.assertEqual(res2["composite_risk_score"], 0.15)
        self.assertEqual(res2["composite_verdict"], "benign")
        self.assertIn("session:DEVICE_CONTEXT_CHANGED", res2["all_triggered_indicators"])
        self.assertNotIn("session:RAPID_SOURCE_IP_CHANGE", res2["all_triggered_indicators"])
        self.assertNotIn("session:SUSPICIOUS_CONTEXT_MISMATCH", res2["all_triggered_indicators"])

    def test_modifier_rapid_source_ip_change_independent_score(self):
        # IP changed rapidly (<60s), but device constant (e.g. mobile VPN toggle)
        # Yields RAPID_SOURCE_IP_CHANGE (+0.10) without DEVICE_CONTEXT_CHANGED or SUSPICIOUS_CONTEXT_MISMATCH
        ev1 = {
            "session_id": "MOD-RAPIDIP-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CONSTANT-01",
        }
        ev2 = {
            "session_id": "MOD-RAPIDIP-01",
            "timestamp": "2026-10-15T12:00:20Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "198.51.100.88",
            "device_id": "DEV-CONSTANT-01",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(ev2, session_tracker=self.session_tracker)

        self.assertEqual(res2["composite_risk_score"], 0.10)
        self.assertEqual(res2["composite_verdict"], "benign")
        self.assertIn("session:RAPID_SOURCE_IP_CHANGE", res2["all_triggered_indicators"])
        self.assertNotIn("session:DEVICE_CONTEXT_CHANGED", res2["all_triggered_indicators"])
        self.assertNotIn("session:SUSPICIOUS_CONTEXT_MISMATCH", res2["all_triggered_indicators"])

    def test_lazy_tls_analyzer_creation_when_analyzer_omitted(self):
        # Call analyze_event_composite without passing tls_analyzer (default None)
        # When event contains certificate_telemetry, detector must auto-instantiate TLSAnalyzer
        event = {
            "session_id": "COMP-LAZY-TLS-01",
            "redirect_count": 1,
            "redirect_chain": ["login.company.com"],
            "tls_anomaly": False,
            "certificate_telemetry": {
                "subject_cn": "mismatch-host.com",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }
        # Note: tls_analyzer is intentionally omitted (defaults to None)
        res = self.detector.analyze_event_composite(event, reference_time=self.ref_time)

        self.assertIsNotNone(res["tls_analysis"])
        self.assertTrue(res["tls_analysis"]["is_anomaly"])
        self.assertIn("tls:CERT_HOSTNAME_MISMATCH", res["all_triggered_indicators"])
        self.assertEqual(res["composite_risk_score"], 0.30)

    # -------------------------------------------------------------
    # 7. Replay-Related Modifiers and Multi-Signal Compounds
    # -------------------------------------------------------------
    def test_modifier_datacenter_source_transition_independent_score(self):
        # Residential -> datacenter transition: base 0.0 + modifier 0.20 = 0.20 (benign)
        ev1 = {
            "session_id": "COMP-DTR-01",
            "timestamp": "2026-10-15T15:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "198.51.100.10",
            "device_id": "DEV-01",
            "asn_type": "residential",
        }
        ev2 = {
            "session_id": "COMP-DTR-01",
            "timestamp": "2026-10-15T15:05:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "203.0.113.10",
            "device_id": "DEV-01",
            "asn_type": "datacenter",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(ev2, session_tracker=self.session_tracker)

        self.assertEqual(res2["composite_risk_score"], 0.20)
        self.assertEqual(res2["composite_verdict"], "benign")
        self.assertIn("session:DATACENTER_SOURCE_TRANSITION", res2["all_triggered_indicators"])

    def test_modifier_client_platform_divergence_independent_score(self):
        # Platform shift: windows -> linux: base 0.0 + modifier 0.25 = 0.25 (benign)
        ev1 = {
            "session_id": "COMP-CPD-01",
            "timestamp": "2026-10-15T15:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "windows",
        }
        ev2 = {
            "session_id": "COMP-CPD-01",
            "timestamp": "2026-10-15T15:05:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "linux",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(ev2, session_tracker=self.session_tracker)

        self.assertEqual(res2["composite_risk_score"], 0.25)
        self.assertEqual(res2["composite_verdict"], "benign")
        self.assertIn("session:CLIENT_PLATFORM_DIVERGENCE", res2["all_triggered_indicators"])

    def test_modifier_concurrent_session_bifurcation_independent_score(self):
        # Alternating IPs across 4 events within 120s (with inter-arrival > 60s between 3 & 4 to isolate from rapid IP modifier)
        # Base 0.0 + modifier 0.25 = 0.25 (benign)
        ip_a, ip_b = "192.0.2.1", "198.51.100.2"
        evs = [
            {"session_id": "COMP-BIF-01", "timestamp": "2026-10-15T16:00:00Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "COMP-BIF-01", "timestamp": "2026-10-15T16:00:15Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_b, "device_id": "DEV-01"},
            {"session_id": "COMP-BIF-01", "timestamp": "2026-10-15T16:00:30Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "COMP-BIF-01", "timestamp": "2026-10-15T16:01:35Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_b, "device_id": "DEV-01"},
        ]
        for ev in evs[:-1]:
            self.detector.analyze_event_composite(ev, session_tracker=self.session_tracker)

        res4 = self.detector.analyze_event_composite(evs[-1], session_tracker=self.session_tracker)
        self.assertEqual(res4["composite_risk_score"], 0.25)
        self.assertEqual(res4["composite_verdict"], "benign")
        self.assertIn("session:CONCURRENT_SESSION_BIFURCATION", res4["all_triggered_indicators"])

    def test_modifier_token_binding_failure_independent_score(self):
        # Token binding failure alone: base 0.0 + modifier 0.35 = 0.35 (benign)
        # 1. With session tracker
        ev_with_tracker = {
            "session_id": "COMP-TB-01",
            "timestamp": "2026-10-15T17:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "token_binding_status": "failed",
        }
        res_wt = self.detector.analyze_event_composite(ev_with_tracker, session_tracker=self.session_tracker)
        self.assertEqual(res_wt["composite_risk_score"], 0.35)
        self.assertEqual(res_wt["composite_verdict"], "benign")
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_wt["all_triggered_indicators"])

        # 2. Without session tracker (standalone fallback)
        ev_without_tracker = {
            "session_id": "COMP-TB-02",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "token_binding_status": "key_mismatch",
        }
        res_wot = self.detector.analyze_event_composite(ev_without_tracker)
        self.assertEqual(res_wot["composite_risk_score"], 0.35)
        self.assertEqual(res_wot["composite_verdict"], "benign")
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_wot["all_triggered_indicators"])

    def test_corroborating_signals_crossing_verdict_threshold(self):
        # 1. TOKEN_BINDING_FAILURE (0.35) + DATACENTER_SOURCE_TRANSITION (0.20) = 0.55 -> suspicious
        ev1 = {
            "session_id": "COMP-CORROB-01",
            "timestamp": "2026-10-15T18:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "198.51.100.1",
            "device_id": "DEV-01",
            "asn_type": "residential",
        }
        ev2 = {
            "session_id": "COMP-CORROB-01",
            "timestamp": "2026-10-15T18:05:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "203.0.113.1",
            "device_id": "DEV-01",
            "asn_type": "datacenter",
            "token_binding_status": "failed",
        }
        self.detector.analyze_event_composite(ev1, session_tracker=self.session_tracker)
        res2 = self.detector.analyze_event_composite(ev2, session_tracker=self.session_tracker)

        self.assertEqual(res2["composite_risk_score"], 0.55)
        self.assertEqual(res2["composite_verdict"], "suspicious")
        self.assertIn("session:TOKEN_BINDING_FAILURE", res2["all_triggered_indicators"])
        self.assertIn("session:DATACENTER_SOURCE_TRANSITION", res2["all_triggered_indicators"])

        # 2. CONCURRENT_SESSION_BIFURCATION (0.25) + CLIENT_PLATFORM_DIVERGENCE (0.25) = 0.50 -> suspicious (boundary)
        ip_a, ip_b = "192.0.2.1", "198.51.100.2"
        tracker_bif = SessionTracker()
        evs = [
            {"session_id": "COMP-CORROB-02", "timestamp": "2026-10-15T19:00:00Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01", "client_platform": "windows"},
            {"session_id": "COMP-CORROB-02", "timestamp": "2026-10-15T19:00:15Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_b, "device_id": "DEV-01", "client_platform": "windows"},
            {"session_id": "COMP-CORROB-02", "timestamp": "2026-10-15T19:00:30Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01", "client_platform": "windows"},
            {"session_id": "COMP-CORROB-02", "timestamp": "2026-10-15T19:01:35Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_b, "device_id": "DEV-01", "client_platform": "linux"},
        ]
        for ev in evs[:-1]:
            self.detector.analyze_event_composite(ev, session_tracker=tracker_bif)
        res_bound = self.detector.analyze_event_composite(evs[-1], session_tracker=tracker_bif)

        self.assertEqual(res_bound["composite_risk_score"], 0.50)
        self.assertEqual(res_bound["composite_verdict"], "suspicious")
        self.assertIn("session:CONCURRENT_SESSION_BIFURCATION", res_bound["all_triggered_indicators"])
        self.assertIn("session:CLIENT_PLATFORM_DIVERGENCE", res_bound["all_triggered_indicators"])

    def test_multi_signal_score_cap_with_replay_indicators(self):
        # Base redirect (0.50) + TOKEN_BINDING_FAILURE (0.35) + CONCURRENT_SESSION_BIFURCATION (0.25)
        # Sum = 1.10 -> capped at 1.0
        ip_a, ip_b = "192.0.2.1", "198.51.100.2"
        tracker_cap = SessionTracker()
        evs = [
            {"session_id": "COMP-CAP-01", "timestamp": "2026-10-15T20:00:00Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "COMP-CAP-01", "timestamp": "2026-10-15T20:00:20Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_b, "device_id": "DEV-01"},
            {"session_id": "COMP-CAP-01", "timestamp": "2026-10-15T20:00:40Z", "redirect_count": 1, "redirect_chain": ["idp.example.com"], "tls_anomaly": False, "source_ip": ip_a, "device_id": "DEV-01"},
            {
                "session_id": "COMP-CAP-01",
                "timestamp": "2026-10-15T20:01:00Z",
                "redirect_count": 4, # triggers EXCESSIVE_REDIRECT_COUNT (+0.30) + HIGH_TRANSITION_COMPLEXITY (+0.20)
                "redirect_chain": ["a.com", "b.com", "c.com", "d.com"],
                "tls_anomaly": False,
                "source_ip": ip_b,
                "device_id": "DEV-01",
                "token_binding_status": "failed", # (+0.35)
                # BIFURCATION (+0.25)
            },
        ]
        for ev in evs[:-1]:
            self.detector.analyze_event_composite(ev, session_tracker=tracker_cap)

        res_cap = self.detector.analyze_event_composite(evs[-1], session_tracker=tracker_cap)
        self.assertEqual(res_cap["composite_risk_score"], 1.0)
        self.assertEqual(res_cap["composite_verdict"], "suspicious")
        self.assertIn("base:EXCESSIVE_REDIRECT_COUNT", res_cap["all_triggered_indicators"])
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_cap["all_triggered_indicators"])
        self.assertIn("session:CONCURRENT_SESSION_BIFURCATION", res_cap["all_triggered_indicators"])

    def test_composite_replay_label_leakage_resistance(self):
        # Confirm that passing scenario, ground_truth, or replay_indicator never influences composite detection
        clean_event = {
            "session_id": "COMP-LEAK-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "token_binding_status": "valid",
        }
        tainted_event = {
            "session_id": "COMP-LEAK-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "token_binding_status": "valid",
            "scenario": "evil_proxy_replay_attack",
            "ground_truth": "suspicious",
            "replay_indicator": True,
        }
        res_clean = self.detector.analyze_event_composite(clean_event)
        res_tainted = self.detector.analyze_event_composite(tainted_event)

        self.assertEqual(res_clean["composite_risk_score"], res_tainted["composite_risk_score"])
        self.assertEqual(res_clean["composite_verdict"], res_tainted["composite_verdict"])
        self.assertEqual(res_clean["all_triggered_indicators"], res_tainted["all_triggered_indicators"])
        self.assertEqual(res_clean["composite_explanation"], res_tainted["composite_explanation"])

    def test_composite_token_binding_consistency_on_missing_or_invalid_timestamp(self):
        # Event with missing timestamp and token_binding_status: "failed"
        ev_missing = {
            "session_id": "COMP-TB-CONSIST-01",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "token_binding_status": "failed",
        }
        # Run with session tracker
        tracker = SessionTracker()
        res_with = self.detector.analyze_event_composite(ev_missing, session_tracker=tracker)
        # Run without session tracker (standalone fallback)
        res_without = self.detector.analyze_event_composite(ev_missing)

        # Both must award +0.35 risk score and register session:TOKEN_BINDING_FAILURE
        self.assertEqual(res_with["composite_risk_score"], 0.35)
        self.assertEqual(res_without["composite_risk_score"], 0.35)
        self.assertEqual(res_with["composite_verdict"], "benign")
        self.assertEqual(res_without["composite_verdict"], "benign")
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_with["all_triggered_indicators"])
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_without["all_triggered_indicators"])
        self.assertIn("session:MISSING_TIMESTAMP", res_with["all_triggered_indicators"])

        # Event with invalid timestamp and token_binding_status: "key_mismatch"
        ev_invalid = {
            "session_id": "COMP-TB-CONSIST-02",
            "timestamp": "invalid-timestamp-value",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "token_binding_status": "key_mismatch",
        }
        res_invalid_with = self.detector.analyze_event_composite(ev_invalid, session_tracker=tracker)
        res_invalid_without = self.detector.analyze_event_composite(ev_invalid)
        self.assertEqual(res_invalid_with["composite_risk_score"], 0.35)
        self.assertEqual(res_invalid_without["composite_risk_score"], 0.35)
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_invalid_with["all_triggered_indicators"])
        self.assertIn("session:TOKEN_BINDING_FAILURE", res_invalid_without["all_triggered_indicators"])
        self.assertIn("session:INVALID_TIMESTAMP", res_invalid_with["all_triggered_indicators"])

    def test_composite_out_of_order_does_not_falsely_penalize_from_future_event(self):
        tracker = SessionTracker()
        # Event 1: 12:00:00, DEV-A, 192.0.2.1
        ev1 = {
            "session_id": "COMP-OOO-PRED-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }
        # Event 2: 12:10:00 (arrives 2nd), DEV-B, 198.51.100.9 (different context in future)
        ev2 = {
            "session_id": "COMP-OOO-PRED-01",
            "timestamp": "2026-10-15T12:10:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "198.51.100.9",
            "device_id": "DEV-B",
        }
        # Event 3: 12:02:00 (arrives 3rd, out of order between ev1 and ev2), DEV-A, 192.0.2.1 (identical context to ev1)
        ev3 = {
            "session_id": "COMP-OOO-PRED-01",
            "timestamp": "2026-10-15T12:02:00Z",
            "redirect_count": 1,
            "redirect_chain": ["idp.example.com"],
            "tls_anomaly": False,
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }

        self.detector.analyze_event_composite(ev1, session_tracker=tracker)
        self.detector.analyze_event_composite(ev2, session_tracker=tracker)
        res3 = self.detector.analyze_event_composite(ev3, session_tracker=tracker)

        # Event 3 matches its chronological predecessor ev1, so no device change penalty
        self.assertIn("session:OUT_OF_ORDER_EVENT", res3["all_triggered_indicators"])
        self.assertNotIn("session:DEVICE_CONTEXT_CHANGED", res3["all_triggered_indicators"])
        self.assertEqual(res3["composite_risk_score"], 0.0)
        self.assertEqual(res3["composite_verdict"], "benign")


if __name__ == "__main__":
    unittest.main()
