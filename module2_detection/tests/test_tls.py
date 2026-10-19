import unittest
import sys
from datetime import datetime, timezone
from pathlib import Path

MODULE2_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE2_DIR))

from tls_analyzer import TLSAnalyzer, CertificateTelemetry, TLSAnalysisResult


class TestTLSAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TLSAnalyzer()
        self.ref_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------
    # 1. Normal Certificate Observation
    # -------------------------------------------------------------
    def test_normal_certificate_observation(self):
        event = {
            "session_id": "TLS-NORM-01",
            "redirect_chain": ["login.microsoftonline.com"],
            "certificate_telemetry": {
                "subject_cn": "login.microsoftonline.com",
                "subject_alt_names": ["login.microsoftonline.com", "*.microsoft.com"],
                "issuer_org": "DigiCert Inc",
                "issuer_cn": "DigiCert Global Root G2",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "is_self_signed": False,
                "sni_hostname": "login.microsoftonline.com",
                "validation_status": "valid",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["confidence"], "high")
        self.assertIn("NORMAL_CERTIFICATE_OBSERVED", result["indicators"])
        self.assertNotIn("CERT_HOSTNAME_MISMATCH", result["indicators"])
        self.assertNotIn("CERT_EXPIRED", result["indicators"])

    def test_certificate_telemetry_dataclass_input(self):
        # Support CertificateTelemetry dataclass instance as input
        cert_data = CertificateTelemetry(
            subject_cn="login.microsoftonline.com",
            subject_alt_names=["login.microsoftonline.com"],
            issuer_org="DigiCert Inc",
            not_before="2026-01-01T00:00:00Z",
            not_after="2026-12-31T23:59:59Z",
            is_self_signed=False,
            validation_status="valid",
        )
        event = {
            "session_id": "TLS-DC-01",
            "redirect_chain": ["login.microsoftonline.com"],
            "certificate_telemetry": cert_data,
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertFalse(result["is_anomaly"])
        self.assertIn("NORMAL_CERTIFICATE_OBSERVED", result["indicators"])

    # -------------------------------------------------------------
    # 2. Hostname Matching & Explicit Observed Host
    # -------------------------------------------------------------
    def test_hostname_mismatch(self):
        event = {
            "session_id": "TLS-MISMATCH-01",
            "redirect_chain": ["login.target.com"],
            "certificate_telemetry": {
                "subject_cn": "evil-proxy.com",
                "subject_alt_names": ["evil-proxy.com", "phish.evil.com"],
                "issuer_org": "Let's Encrypt",
                "not_before": "2026-09-01T00:00:00Z",
                "not_after": "2026-11-30T23:59:59Z",
                "is_self_signed": False,
                "validation_status": "valid",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("CERT_HOSTNAME_MISMATCH", result["indicators"])
        self.assertTrue(len(result["legitimate_causes"]) > 0)
        self.assertIn("Split-horizon DNS", result["legitimate_causes"][0])

    def test_explicit_observed_hostname_precedence(self):
        # Even if redirect_chain starts with app.corp.local, explicit observed_hostname is verified
        event = {
            "session_id": "TLS-EXPL-01",
            "redirect_chain": ["app.corp.local", "login.microsoftonline.com"],
            "certificate_telemetry": {
                "observed_hostname": "login.microsoftonline.com",
                "subject_cn": "login.microsoftonline.com",
                "subject_alt_names": ["login.microsoftonline.com"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["details"]["target_host"], "login.microsoftonline.com")

    def test_hostname_wildcard_matching(self):
        event = {
            "session_id": "TLS-WILDCARD-01",
            "redirect_chain": ["sso.corp.net"],
            "certificate_telemetry": {
                "subject_cn": "*.corp.net",
                "subject_alt_names": ["*.corp.net"],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "is_self_signed": False,
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertFalse(result["is_anomaly"])
        self.assertNotIn("CERT_HOSTNAME_MISMATCH", result["indicators"])

    def test_trusted_idp_host_allowlist_check(self):
        analyzer_with_trust = TLSAnalyzer(expected_trusted_hosts=["login.microsoftonline.com"])
        event = {
            "session_id": "TLS-UNTRUSTED-HOST-01",
            "redirect_chain": ["phish-proxy.com"],
            "certificate_telemetry": {
                "subject_cn": "phish-proxy.com",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }

        result = analyzer_with_trust.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertTrue(result["is_anomaly"])
        self.assertIn("UNTRUSTED_AUTH_HOST", result["indicators"])

    # -------------------------------------------------------------
    # 3. Temporal Validity & Explicit UTC Policy on Naive Dates
    # -------------------------------------------------------------
    def test_naive_timestamp_interpreted_as_utc(self):
        # Naive date string without timezone offset must be interpreted as UTC
        event = {
            "session_id": "TLS-NAIVE-DATE-01",
            "redirect_chain": ["idp.example.com"],
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "2026-01-01T00:00:00",  # naive
                "not_after": "2026-12-31T23:59:59",   # naive
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertFalse(result["is_anomaly"])
        self.assertNotIn("MALFORMED_CERTIFICATE_DATE", result["indicators"])

    def test_expired_certificate(self):
        event = {
            "session_id": "TLS-EXPIRED-01",
            "redirect_chain": ["idp.example.com"],
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "2025-08-01T00:00:00Z",
                "not_after": "2026-08-01T00:00:00Z",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("CERT_EXPIRED", result["indicators"])

    def test_not_yet_valid_certificate(self):
        event = {
            "session_id": "TLS-FUTURE-01",
            "redirect_chain": ["idp.example.com"],
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "2026-11-01T00:00:00Z",
                "not_after": "2027-11-01T00:00:00Z",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("CERT_NOT_YET_VALID", result["indicators"])

    # -------------------------------------------------------------
    # 4. Untrusted Self-Signed & Enterprise Proxy Exemption
    # -------------------------------------------------------------
    def test_untrusted_self_signed_certificate(self):
        event = {
            "session_id": "TLS-SELFSIGN-01",
            "redirect_chain": ["lab-idp.local"],
            "certificate_telemetry": {
                "subject_cn": "lab-idp.local",
                "is_self_signed": True,
                "validation_status": "untrusted_root",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("UNTRUSTED_SELF_SIGNED_CERT", result["indicators"])
        causes_text = " ".join(result["legitimate_causes"])
        self.assertIn("SSL/TLS inspection", causes_text)

    def test_enterprise_proxy_issuer_not_flagged_as_anomaly(self):
        # An issuer containing 'proxy' (e.g. corporate forward proxy) must NOT trigger anomaly
        event = {
            "session_id": "TLS-CORP-PROXY-01",
            "redirect_chain": ["login.microsoftonline.com"],
            "certificate_telemetry": {
                "subject_cn": "login.microsoftonline.com",
                "issuer_org": "Corporate Secure Proxy Authority",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "validation_status": "valid",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertFalse(result["is_anomaly"])
        self.assertNotIn("SUSPICIOUS_ISSUER_KEYWORD", result["indicators"])

    def test_suspicious_issuer_keyword_is_investigative_only(self):
        # A keyword like 'evil' is emitted as investigative flag but does not trigger is_anomaly alone
        event = {
            "session_id": "TLS-EVIL-01",
            "redirect_chain": ["login.service.com"],
            "certificate_telemetry": {
                "subject_cn": "login.service.com",
                "issuer_org": "Evil Phish Authority",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
                "validation_status": "valid",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertIn("SUSPICIOUS_ISSUER_KEYWORD", result["indicators"])
        self.assertFalse(result["is_anomaly"])  # Not an anomaly on its own

    # -------------------------------------------------------------
    # 5. SNI vs Target Host Inconsistency
    # -------------------------------------------------------------
    def test_sni_host_mismatch(self):
        event = {
            "session_id": "TLS-SNI-01",
            "redirect_chain": ["login.company.com"],
            "certificate_telemetry": {
                "subject_cn": "login.company.com",
                "sni_hostname": "fronting.cdn.external.net",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("SNI_HOST_MISMATCH", result["indicators"])

    # -------------------------------------------------------------
    # 6. Missing / Incomplete Telemetry (MUST NOT BE AN ANOMALY)
    # -------------------------------------------------------------
    def test_missing_certificate_telemetry_not_treated_as_anomaly(self):
        event = {
            "session_id": "TLS-NONE-01",
            "redirect_chain": ["idp.example.com"],
        }

        result = self.analyzer.analyze_event_tls(event)

        self.assertFalse(result["is_anomaly"])
        self.assertIn("UNOBSERVED_TLS_TELEMETRY", result["indicators"])
        self.assertIn("missing_telemetry", result["details"])

    def test_empty_certificate_telemetry_not_treated_as_anomaly(self):
        event = {
            "session_id": "TLS-EMPTY-01",
            "redirect_chain": ["idp.example.com"],
            "certificate_telemetry": {},
        }

        result = self.analyzer.analyze_event_tls(event)

        self.assertFalse(result["is_anomaly"])
        self.assertIn("INCOMPLETE_CERTIFICATE_TELEMETRY", result["indicators"])

    # -------------------------------------------------------------
    # 7. Malformed Input Handling
    # -------------------------------------------------------------
    def test_malformed_certificate_dates_handled_gracefully(self):
        event = {
            "session_id": "TLS-BADDATE-01",
            "redirect_chain": ["idp.example.com"],
            "certificate_telemetry": {
                "subject_cn": "idp.example.com",
                "not_before": "not-a-valid-date",
                "not_after": "corrupted-date-value",
            },
        }

        result = self.analyzer.analyze_event_tls(event, reference_time=self.ref_time)
        self.assertIn("MALFORMED_CERTIFICATE_DATE", result["indicators"])

    def test_malformed_telemetry_type(self):
        event = {
            "session_id": "TLS-BADTYPE-01",
            "certificate_telemetry": "not-a-dictionary",
        }

        result = self.analyzer.analyze_event_tls(event)

        self.assertFalse(result["is_anomaly"])
        self.assertIn("MALFORMED_CERTIFICATE_TELEMETRY", result["indicators"])

    # -------------------------------------------------------------
    # 8. Backward Compatibility with Legacy Events
    # -------------------------------------------------------------
    def test_legacy_backward_compatibility_tls_anomaly_true(self):
        legacy_event = {
            "session_id": "LAB-002",
            "redirect_count": 4,
            "redirect_chain": ["lab-login.local", "proxy.local"],
            "tls_anomaly": True,
        }

        result = self.analyzer.analyze_event_tls(legacy_event)

        self.assertTrue(result["is_anomaly"])
        self.assertIn("LEGACY_TLS_ANOMALY_FLAG", result["indicators"])

    def test_legacy_backward_compatibility_tls_anomaly_false(self):
        legacy_event = {
            "session_id": "LAB-001",
            "redirect_count": 1,
            "redirect_chain": ["lab-idp.local"],
            "tls_anomaly": False,
        }

        result = self.analyzer.analyze_event_tls(legacy_event)

        self.assertFalse(result["is_anomaly"])
        self.assertIn("UNOBSERVED_TLS_TELEMETRY", result["indicators"])

    # -------------------------------------------------------------
    # 9. Zero-Shortcut Leakage Prevention
    # -------------------------------------------------------------
    def test_zero_shortcut_leakage(self):
        base_event = {
            "session_id": "TLS-SHORTCUT-01",
            "redirect_chain": ["auth.corp.com"],
            "certificate_telemetry": {
                "subject_cn": "auth.corp.com",
                "issuer_org": "DigiCert Inc",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T23:59:59Z",
            },
        }

        ev_a = dict(base_event, scenario="normal", replay_indicator=False, ground_truth="benign")
        res_a = self.analyzer.analyze_event_tls(ev_a, reference_time=self.ref_time)

        ev_b = dict(base_event, scenario="suspicious_simulation", replay_indicator=True, ground_truth="suspicious")
        res_b = self.analyzer.analyze_event_tls(ev_b, reference_time=self.ref_time)

        self.assertEqual(res_a["is_anomaly"], res_b["is_anomaly"])
        self.assertEqual(res_a["indicators"], res_b["indicators"])
        self.assertEqual(res_a["explanation"], res_b["explanation"])


if __name__ == "__main__":
    unittest.main()
