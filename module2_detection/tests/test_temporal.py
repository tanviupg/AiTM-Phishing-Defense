import unittest
import sys
from datetime import datetime, timezone
from pathlib import Path

MODULE2_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE2_DIR))

from session_tracker import SessionTracker, CorrelationResult


class TestSessionTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = SessionTracker(
            correlation_window_seconds=3600.0,
            rapid_source_window_seconds=60.0,
        )

    # -------------------------------------------------------------
    # 1. Normal Continuation
    # -------------------------------------------------------------
    def test_normal_continuation(self):
        event1 = {
            "session_id": "SES-NORMAL-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        }
        event2 = {
            "session_id": "SES-NORMAL-01",
            "timestamp": "2026-10-14T12:05:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-CORP-01",
        }

        res1 = self.tracker.correlate_event(event1)
        self.assertFalse(res1["is_correlated"])
        self.assertIn("INITIAL_SESSION_EVENT", res1["indicators"])

        res2 = self.tracker.correlate_event(event2)
        self.assertTrue(res2["is_correlated"])
        self.assertEqual(res2["delta_seconds"], 300.0)
        self.assertIn("NORMAL_SESSION_CONTINUATION", res2["indicators"])
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res2["indicators"])
        self.assertNotIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])

    # -------------------------------------------------------------
    # 2. Suspicious Context Mismatch (Simultaneous Device & Rapid IP Change)
    # -------------------------------------------------------------
    def test_suspicious_synthetic_context_mismatch(self):
        event1 = {
            "session_id": "SES-MISMATCH-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        }
        # 15 seconds later: session reused from a completely different device and IP
        event2 = {
            "session_id": "SES-MISMATCH-01",
            "timestamp": "2026-10-14T12:00:15+00:00",
            "source_ip": "198.51.100.50",
            "device_id": "DEV-ATTACKER-99",
        }

        self.tracker.correlate_event(event1)
        res2 = self.tracker.correlate_event(event2)

        self.assertTrue(res2["is_correlated"])
        self.assertEqual(res2["delta_seconds"], 15.0)
        self.assertIn("DEVICE_CONTEXT_CHANGED", res2["indicators"])
        self.assertIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])
        self.assertIn("SUSPICIOUS_CONTEXT_MISMATCH", res2["indicators"])
        self.assertIn("simultaneous device mismatch", res2["explanation"])

    # -------------------------------------------------------------
    # 3. Benign IP Roaming (Device Consistent, Sufficient Time Delta)
    # -------------------------------------------------------------
    def test_benign_ip_roaming(self):
        event1 = {
            "session_id": "SES-ROAM-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-LAPTOP-01",
        }
        # 10 minutes later: employee moves from office Wi-Fi to cellular hotspot on same device
        event2 = {
            "session_id": "SES-ROAM-01",
            "timestamp": "2026-10-14T12:10:00+00:00",
            "source_ip": "203.0.113.88",
            "device_id": "DEV-LAPTOP-01",
        }

        self.tracker.correlate_event(event1)
        res2 = self.tracker.correlate_event(event2)

        self.assertTrue(res2["is_correlated"])
        self.assertEqual(res2["delta_seconds"], 600.0)
        self.assertIn("BENIGN_IP_ROAMING_PLAUSIBLE", res2["indicators"])
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res2["indicators"])
        self.assertNotIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])
        self.assertNotIn("SUSPICIOUS_CONTEXT_MISMATCH", res2["indicators"])

    # -------------------------------------------------------------
    # 4. Rapid Source Changes Without Device Change
    # -------------------------------------------------------------
    def test_rapid_source_changes_without_device_change(self):
        event1 = {
            "session_id": "SES-RAPID-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-PHONE-01",
        }
        # 20 seconds later: rapid network shift (e.g. VPN toggle) on same device
        event2 = {
            "session_id": "SES-RAPID-01",
            "timestamp": "2026-10-14T12:00:20+00:00",
            "source_ip": "198.51.100.99",
            "device_id": "DEV-PHONE-01",
        }

        self.tracker.correlate_event(event1)
        res2 = self.tracker.correlate_event(event2)

        self.assertTrue(res2["is_correlated"])
        self.assertEqual(res2["delta_seconds"], 20.0)
        self.assertIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res2["indicators"])
        self.assertNotIn("SUSPICIOUS_CONTEXT_MISMATCH", res2["indicators"])

    # -------------------------------------------------------------
    # 5. Missing Telemetry & Malformed Timestamps
    # -------------------------------------------------------------
    def test_missing_telemetry_fields(self):
        event = {
            "session_id": "SES-MISSING-01",
            "timestamp": "2026-10-14T12:00:00Z",
            # source_ip and device_id omitted
        }
        res = self.tracker.correlate_event(event)

        self.assertIn("MISSING_TELEMETRY", res["indicators"])
        self.assertIn("source_ip", res["explanation"])
        self.assertIn("device_id", res["explanation"])

    def test_missing_timestamp(self):
        event = {
            "session_id": "SES-NOTS-01",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        res = self.tracker.correlate_event(event)

        self.assertIn("MISSING_TIMESTAMP", res["indicators"])
        self.assertFalse(res["is_correlated"])

    def test_invalid_timestamp(self):
        event = {
            "session_id": "SES-BADTS-01",
            "timestamp": "not-a-valid-timestamp-string",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        res = self.tracker.correlate_event(event)

        self.assertIn("INVALID_TIMESTAMP", res["indicators"])
        self.assertFalse(res["is_correlated"])

    # -------------------------------------------------------------
    # 6. Duplicate Events
    # -------------------------------------------------------------
    def test_duplicate_events(self):
        event = {
            "session_id": "SES-DUP-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }

        res1 = self.tracker.correlate_event(event)
        self.assertNotIn("DUPLICATE_EVENT", res1["indicators"])

        res2 = self.tracker.correlate_event(event)
        self.assertTrue(res2["is_correlated"])
        self.assertIn("DUPLICATE_EVENT", res2["indicators"])

    # -------------------------------------------------------------
    # 7. Out-of-Order Events
    # -------------------------------------------------------------
    def test_out_of_order_events(self):
        event_later = {
            "session_id": "SES-OOO-01",
            "timestamp": "2026-10-14T12:10:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        # Arrives second, but its timestamp is 5 minutes earlier
        event_earlier = {
            "session_id": "SES-OOO-01",
            "timestamp": "2026-10-14T12:05:00+00:00",
            "source_ip": "192.0.2.20",
            "device_id": "DEV-01",
        }

        self.tracker.correlate_event(event_later)
        res = self.tracker.correlate_event(event_earlier)

        self.assertIn("OUT_OF_ORDER_EVENT", res["indicators"])

    # -------------------------------------------------------------
    # 8. Window Expiry and Pruning
    # -------------------------------------------------------------
    def test_window_expiry(self):
        # Tracker configured with 3600s (1h) correlation window
        event1 = {
            "session_id": "SES-EXPIRY-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        # 3 hours later (> 3600s)
        event2 = {
            "session_id": "SES-EXPIRY-01",
            "timestamp": "2026-10-14T15:00:00+00:00",
            "source_ip": "198.51.100.99",
            "device_id": "DEV-02",
        }

        self.tracker.correlate_event(event1)
        res2 = self.tracker.correlate_event(event2)

        # Should report window expired and reset baseline
        self.assertIn("SESSION_WINDOW_EXPIRED", res2["indicators"])
        self.assertFalse(res2["is_correlated"])
        self.assertEqual(res2["event_count"], 1)

    def test_prune_expired_sessions(self):
        event = {
            "session_id": "SES-PRUNE-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        self.tracker.correlate_event(event)

        # Check pruning 30 minutes later (not expired)
        pruned_early = self.tracker.prune_expired_sessions(
            reference_time=datetime(2026, 10, 14, 12, 30, tzinfo=timezone.utc)
        )
        self.assertEqual(pruned_early, 0)

        # Check pruning 2 hours later (expired)
        pruned_late = self.tracker.prune_expired_sessions(
            reference_time=datetime(2026, 10, 14, 14, 30, tzinfo=timezone.utc)
        )
        self.assertEqual(pruned_late, 1)

    # -------------------------------------------------------------
    # 9. Label Leakage Prevention
    # -------------------------------------------------------------
    def test_label_leakage_prevention(self):
        base_event_1 = {
            "session_id": "SES-LEAKAGE-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        base_event_2 = {
            "session_id": "SES-LEAKAGE-01",
            "timestamp": "2026-10-14T12:00:30+00:00",
            "source_ip": "198.51.100.20",
            "device_id": "DEV-02",
        }

        # Run A: with normal labels
        tracker_a = SessionTracker()
        ev1_a = dict(base_event_1, scenario="normal", replay_indicator=False, ground_truth="benign")
        ev2_a = dict(base_event_2, scenario="normal", replay_indicator=False, ground_truth="benign")
        tracker_a.correlate_event(ev1_a)
        res_a = tracker_a.correlate_event(ev2_a)

        # Run B: with suspicious labels
        tracker_b = SessionTracker()
        ev1_b = dict(base_event_1, scenario="suspicious_simulation", replay_indicator=True, ground_truth="suspicious")
        ev2_b = dict(base_event_2, scenario="suspicious_simulation", replay_indicator=True, ground_truth="suspicious")
        tracker_b.correlate_event(ev1_b)
        res_b = tracker_b.correlate_event(ev2_b)

        # Results must be identical
        self.assertEqual(res_a["indicators"], res_b["indicators"])
        self.assertEqual(res_a["delta_seconds"], res_b["delta_seconds"])
        self.assertEqual(res_a["is_correlated"], res_b["is_correlated"])
        self.assertEqual(res_a["explanation"], res_b["explanation"])

    # -------------------------------------------------------------
    # 10. Multi-Event Sequences and State Isolation
    # -------------------------------------------------------------
    def test_multi_event_session_sequence(self):
        # Multi-turn sequence (4 events) within the same session
        ev1 = {
            "session_id": "SES-MULTI-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        }
        ev2 = {
            "session_id": "SES-MULTI-01",
            "timestamp": "2026-10-14T12:05:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-USER-01",
        }
        ev3 = {
            "session_id": "SES-MULTI-01",
            "timestamp": "2026-10-14T12:05:25+00:00",
            "source_ip": "198.51.100.99",
            "device_id": "DEV-ATTACKER-99",
        }
        ev4 = {
            "session_id": "SES-MULTI-01",
            "timestamp": "2026-10-14T12:05:50+00:00",
            "source_ip": "198.51.100.99",
            "device_id": "DEV-ATTACKER-99",
        }

        # Event 1: Initial anchor
        res1 = self.tracker.correlate_event(ev1)
        self.assertFalse(res1["is_correlated"])
        self.assertEqual(res1["event_count"], 1)
        self.assertIn("INITIAL_SESSION_EVENT", res1["indicators"])

        # Event 2: Normal continuation (5m later)
        res2 = self.tracker.correlate_event(ev2)
        self.assertTrue(res2["is_correlated"])
        self.assertEqual(res2["event_count"], 2)
        self.assertEqual(res2["delta_seconds"], 300.0)
        self.assertIn("NORMAL_SESSION_CONTINUATION", res2["indicators"])

        # Event 3: Suspicious context mismatch (25s later, new device + new IP)
        res3 = self.tracker.correlate_event(ev3)
        self.assertTrue(res3["is_correlated"])
        self.assertEqual(res3["event_count"], 3)
        self.assertEqual(res3["delta_seconds"], 25.0)
        self.assertIn("SUSPICIOUS_CONTEXT_MISMATCH", res3["indicators"])
        self.assertIn("DEVICE_CONTEXT_CHANGED", res3["indicators"])
        self.assertIn("RAPID_SOURCE_IP_CHANGE", res3["indicators"])

        # Event 4: Continuation from attacker's newly established context (25s later, same attacker IP + dev)
        res4 = self.tracker.correlate_event(ev4)
        self.assertTrue(res4["is_correlated"])
        self.assertEqual(res4["event_count"], 4)
        self.assertEqual(res4["delta_seconds"], 25.0)
        self.assertIn("NORMAL_SESSION_CONTINUATION", res4["indicators"])
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res4["indicators"])

    def test_interleaved_multi_session_isolation(self):
        # Verify that concurrent events from different sessions do not cross-contaminate state
        alpha_1 = {
            "session_id": "SES-ALPHA-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "10.0.0.1",
            "device_id": "DEV-ALPHA-1",
        }
        beta_1 = {
            "session_id": "SES-BETA-01",
            "timestamp": "2026-10-14T12:01:00+00:00",
            "source_ip": "10.0.0.2",
            "device_id": "DEV-BETA-1",
        }
        alpha_2 = {
            "session_id": "SES-ALPHA-01",
            "timestamp": "2026-10-14T12:02:00+00:00",
            "source_ip": "10.0.0.1",
            "device_id": "DEV-ALPHA-1",
        }
        beta_2 = {
            "session_id": "SES-BETA-01",
            "timestamp": "2026-10-14T12:03:00+00:00",
            "source_ip": "198.51.100.5",
            "device_id": "DEV-BETA-1",
        }

        # Interleaved arrivals: Alpha 1 -> Beta 1 -> Alpha 2 -> Beta 2
        res_a1 = self.tracker.correlate_event(alpha_1)
        res_b1 = self.tracker.correlate_event(beta_1)
        res_a2 = self.tracker.correlate_event(alpha_2)
        res_b2 = self.tracker.correlate_event(beta_2)

        # Alpha 2 should correlate strictly against Alpha 1 (delta 120s, same dev/ip)
        self.assertEqual(res_a2["session_id"], "SES-ALPHA-01")
        self.assertEqual(res_a2["delta_seconds"], 120.0)
        self.assertEqual(res_a2["event_count"], 2)
        self.assertIn("NORMAL_SESSION_CONTINUATION", res_a2["indicators"])

        # Beta 2 should correlate strictly against Beta 1 (delta 120s, roaming IP)
        self.assertEqual(res_b2["session_id"], "SES-BETA-01")
        self.assertEqual(res_b2["delta_seconds"], 120.0)
        self.assertEqual(res_b2["event_count"], 2)
        self.assertIn("BENIGN_IP_ROAMING_PLAUSIBLE", res_b2["indicators"])
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res_b2["indicators"])

    def test_chronological_correlation_after_out_of_order_event(self):
        # Event 1: 12:00:00
        ev1 = {
            "session_id": "SES-REORDER-01",
            "timestamp": "2026-10-14T12:00:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        # Event 3: 12:10:00 (arrives 2nd)
        ev3 = {
            "session_id": "SES-REORDER-01",
            "timestamp": "2026-10-14T12:10:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        # Event 2: 12:05:00 (arrives 3rd, out of order)
        ev2 = {
            "session_id": "SES-REORDER-01",
            "timestamp": "2026-10-14T12:05:00+00:00",
            "source_ip": "192.0.2.99",
            "device_id": "DEV-01",
        }
        # Event 4: 12:15:00 (arrives 4th)
        ev4 = {
            "session_id": "SES-REORDER-01",
            "timestamp": "2026-10-14T12:15:00+00:00",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }

        self.tracker.correlate_event(ev1)
        self.tracker.correlate_event(ev3)
        res_ooo = self.tracker.correlate_event(ev2)
        self.assertIn("OUT_OF_ORDER_EVENT", res_ooo["indicators"])

        # Event 4 should correlate against the chronological latest record (Event 3 at 12:10, IP 192.0.2.10),
        # yielding a 5-minute (300s) delta and identical IP (NORMAL_SESSION_CONTINUATION)
        res4 = self.tracker.correlate_event(ev4)
        self.assertTrue(res4["is_correlated"])
        self.assertEqual(res4["delta_seconds"], 300.0)
        self.assertEqual(res4["event_count"], 4)
        self.assertIn("NORMAL_SESSION_CONTINUATION", res4["indicators"])


    # -------------------------------------------------------------
    # 11. Malformed Input and Constructor Validation
    # -------------------------------------------------------------
    def test_correlate_event_rejects_non_dict_input(self):
        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event(["not", "a", "dict"])
        self.assertIn("must be a dictionary", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event(None)
        self.assertIn("must be a dictionary", str(ctx.exception))

    def test_correlate_event_rejects_empty_or_invalid_session_id(self):
        # Empty string
        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event({"session_id": ""})
        self.assertIn("session_id must be a non-empty string", str(ctx.exception))

        # None
        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event({"session_id": None})
        self.assertIn("session_id must be a non-empty string", str(ctx.exception))

        # Non-string integer
        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event({"session_id": 12345})
        self.assertIn("session_id must be a non-empty string", str(ctx.exception))

        # Missing field
        with self.assertRaises(ValueError) as ctx:
            self.tracker.correlate_event({})
        self.assertIn("session_id must be a non-empty string", str(ctx.exception))

    def test_constructor_rejects_non_positive_windows(self):
        # correlation_window_seconds <= 0
        with self.assertRaises(ValueError) as ctx:
            SessionTracker(correlation_window_seconds=0)
        self.assertIn("correlation_window_seconds must be positive", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            SessionTracker(correlation_window_seconds=-10.0)
        self.assertIn("correlation_window_seconds must be positive", str(ctx.exception))

        # rapid_source_window_seconds <= 0
        with self.assertRaises(ValueError) as ctx:
            SessionTracker(rapid_source_window_seconds=0)
        self.assertIn("rapid_source_window_seconds must be positive", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            SessionTracker(rapid_source_window_seconds=-5.0)
        self.assertIn("rapid_source_window_seconds must be positive", str(ctx.exception))

    # -------------------------------------------------------------
    # 12. Replay Metadata Indicators
    # -------------------------------------------------------------
    def test_datacenter_source_transition(self):
        # 1. Residential to datacenter -> triggers DATACENTER_SOURCE_TRANSITION
        ev1 = {
            "session_id": "SES-ASN-01",
            "timestamp": "2026-10-15T10:00:00Z",
            "source_ip": "198.51.100.1",
            "device_id": "DEV-01",
            "asn_type": "residential",
        }
        ev2 = {
            "session_id": "SES-ASN-01",
            "timestamp": "2026-10-15T10:05:00Z",
            "source_ip": "203.0.113.50",
            "device_id": "DEV-01",
            "asn_type": "datacenter",
        }
        self.tracker.correlate_event(ev1)
        res2 = self.tracker.correlate_event(ev2)
        self.assertIn("DATACENTER_SOURCE_TRANSITION", res2["indicators"])

        # 2. Corporate to datacenter -> triggers DATACENTER_SOURCE_TRANSITION
        ev3 = {
            "session_id": "SES-ASN-02",
            "timestamp": "2026-10-15T10:00:00Z",
            "source_ip": "198.51.100.2",
            "device_id": "DEV-02",
            "asn_type": "corporate",
        }
        ev4 = {
            "session_id": "SES-ASN-02",
            "timestamp": "2026-10-15T10:05:00Z",
            "source_ip": "203.0.113.51",
            "device_id": "DEV-02",
            "asn_type": "datacenter",
        }
        self.tracker.correlate_event(ev3)
        res4 = self.tracker.correlate_event(ev4)
        self.assertIn("DATACENTER_SOURCE_TRANSITION", res4["indicators"])

        # 3. Benign transitions: corporate to residential, residential to residential, missing ASN
        ev5 = {
            "session_id": "SES-ASN-03",
            "timestamp": "2026-10-15T10:00:00Z",
            "source_ip": "198.51.100.3",
            "device_id": "DEV-03",
            "asn_type": "corporate",
        }
        ev6 = {
            "session_id": "SES-ASN-03",
            "timestamp": "2026-10-15T10:05:00Z",
            "source_ip": "198.51.100.4",
            "device_id": "DEV-03",
            "asn_type": "residential",
        }
        self.tracker.correlate_event(ev5)
        res6 = self.tracker.correlate_event(ev6)
        self.assertNotIn("DATACENTER_SOURCE_TRANSITION", res6["indicators"])

        # Datacenter to residential (benign return/cleanup)
        ev7 = {
            "session_id": "SES-ASN-04",
            "timestamp": "2026-10-15T10:00:00Z",
            "source_ip": "203.0.113.50",
            "device_id": "DEV-04",
            "asn_type": "datacenter",
        }
        ev8 = {
            "session_id": "SES-ASN-04",
            "timestamp": "2026-10-15T10:05:00Z",
            "source_ip": "198.51.100.1",
            "device_id": "DEV-04",
            "asn_type": "residential",
        }
        self.tracker.correlate_event(ev7)
        res8 = self.tracker.correlate_event(ev8)
        self.assertNotIn("DATACENTER_SOURCE_TRANSITION", res8["indicators"])

        # Missing ASN metadata -> no trigger
        ev9 = {
            "session_id": "SES-ASN-05",
            "timestamp": "2026-10-15T10:00:00Z",
            "source_ip": "198.51.100.5",
            "device_id": "DEV-05",
        }
        ev10 = {
            "session_id": "SES-ASN-05",
            "timestamp": "2026-10-15T10:05:00Z",
            "source_ip": "203.0.113.60",
            "device_id": "DEV-05",
            "asn_type": "datacenter",
        }
        self.tracker.correlate_event(ev9)
        res10 = self.tracker.correlate_event(ev10)
        self.assertNotIn("DATACENTER_SOURCE_TRANSITION", res10["indicators"])

    def test_concurrent_session_bifurcation(self):
        # 4 chronological events within 120s with alternating IPs: A -> B -> A -> B
        t0 = "2026-10-15T11:00:00Z"
        t1 = "2026-10-15T11:00:20Z"
        t2 = "2026-10-15T11:00:40Z"
        t3 = "2026-10-15T11:01:00Z"
        ip_a = "192.0.2.1"
        ip_b = "198.51.100.2"

        evs = [
            {"session_id": "SES-BIF-01", "timestamp": t0, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-01", "timestamp": t1, "source_ip": ip_b, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-01", "timestamp": t2, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-01", "timestamp": t3, "source_ip": ip_b, "device_id": "DEV-01"},
        ]
        for ev in evs[:-1]:
            r = self.tracker.correlate_event(ev)
            self.assertNotIn("CONCURRENT_SESSION_BIFURCATION", r["indicators"])

        res4 = self.tracker.correlate_event(evs[-1])
        self.assertIn("CONCURRENT_SESSION_BIFURCATION", res4["indicators"])

        # Span > 120s should NOT trigger bifurcation
        evs_slow = [
            {"session_id": "SES-BIF-SLOW", "timestamp": "2026-10-15T11:00:00Z", "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-SLOW", "timestamp": "2026-10-15T11:00:40Z", "source_ip": ip_b, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-SLOW", "timestamp": "2026-10-15T11:01:20Z", "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-SLOW", "timestamp": "2026-10-15T11:03:00Z", "source_ip": ip_b, "device_id": "DEV-01"},
        ]
        for ev in evs_slow:
            res_slow = self.tracker.correlate_event(ev)
        self.assertNotIn("CONCURRENT_SESSION_BIFURCATION", res_slow["indicators"])

        # Non-alternating sequence (A -> A -> B -> B) within 120s should NOT trigger bifurcation
        evs_non_alt = [
            {"session_id": "SES-BIF-NONALT", "timestamp": t0, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-NONALT", "timestamp": t1, "source_ip": ip_a, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-NONALT", "timestamp": t2, "source_ip": ip_b, "device_id": "DEV-01"},
            {"session_id": "SES-BIF-NONALT", "timestamp": t3, "source_ip": ip_b, "device_id": "DEV-01"},
        ]
        for ev in evs_non_alt:
            res_non_alt = self.tracker.correlate_event(ev)
        self.assertNotIn("CONCURRENT_SESSION_BIFURCATION", res_non_alt["indicators"])

    def test_bifurcation_with_out_of_order_arrival_and_session_isolation(self):
        # Out-of-order events arrive: ev0, ev2, ev1, ev3
        # Chronological timestamps: t0 (A), t1 (B), t2 (A), t3 (B)
        t0 = "2026-10-15T12:00:00Z"
        t1 = "2026-10-15T12:00:20Z"
        t2 = "2026-10-15T12:00:40Z"
        t3 = "2026-10-15T12:01:00Z"
        ip_a = "192.0.2.10"
        ip_b = "198.51.100.20"

        ev0 = {"session_id": "SES-BIF-OOO", "timestamp": t0, "source_ip": ip_a, "device_id": "DEV-01"}
        ev1 = {"session_id": "SES-BIF-OOO", "timestamp": t1, "source_ip": ip_b, "device_id": "DEV-01"}
        ev2 = {"session_id": "SES-BIF-OOO", "timestamp": t2, "source_ip": ip_a, "device_id": "DEV-01"}
        ev3 = {"session_id": "SES-BIF-OOO", "timestamp": t3, "source_ip": ip_b, "device_id": "DEV-01"}

        self.tracker.correlate_event(ev0)
        self.tracker.correlate_event(ev2)
        self.tracker.correlate_event(ev1)  # out-of-order
        res3 = self.tracker.correlate_event(ev3)  # arrival finishes chronological sequence
        self.assertIn("CONCURRENT_SESSION_BIFURCATION", res3["indicators"])

        # Session isolation check: interleaved events from separate session do not pollute
        tracker_iso = SessionTracker()
        ev_iso_a1 = {"session_id": "SES-ISO-A", "timestamp": t0, "source_ip": ip_a, "device_id": "DEV-01"}
        ev_iso_b1 = {"session_id": "SES-ISO-B", "timestamp": t0, "source_ip": ip_b, "device_id": "DEV-02"}
        ev_iso_a2 = {"session_id": "SES-ISO-A", "timestamp": t1, "source_ip": ip_a, "device_id": "DEV-01"}
        ev_iso_b2 = {"session_id": "SES-ISO-B", "timestamp": t1, "source_ip": ip_b, "device_id": "DEV-02"}

        tracker_iso.correlate_event(ev_iso_a1)
        tracker_iso.correlate_event(ev_iso_b1)
        res_a2 = tracker_iso.correlate_event(ev_iso_a2)
        res_b2 = tracker_iso.correlate_event(ev_iso_b2)
        self.assertNotIn("CONCURRENT_SESSION_BIFURCATION", res_a2["indicators"])
        self.assertNotIn("CONCURRENT_SESSION_BIFURCATION", res_b2["indicators"])

    def test_client_platform_divergence(self):
        # 1. Platform divergence: windows -> macos
        ev1 = {
            "session_id": "SES-PLAT-01",
            "timestamp": "2026-10-15T13:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "windows",
        }
        ev2 = {
            "session_id": "SES-PLAT-01",
            "timestamp": "2026-10-15T13:02:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "macos",
        }
        self.tracker.correlate_event(ev1)
        res2 = self.tracker.correlate_event(ev2)
        self.assertIn("CLIENT_PLATFORM_DIVERGENCE", res2["indicators"])

        # 2. TLS fingerprint divergence: fp1 -> fp2
        ev3 = {
            "session_id": "SES-PLAT-02",
            "timestamp": "2026-10-15T13:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_tls_fingerprint": "ja4_fingerprint_001",
        }
        ev4 = {
            "session_id": "SES-PLAT-02",
            "timestamp": "2026-10-15T13:02:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_tls_fingerprint": "ja4_fingerprint_002",
        }
        self.tracker.correlate_event(ev3)
        res4 = self.tracker.correlate_event(ev4)
        self.assertIn("CLIENT_PLATFORM_DIVERGENCE", res4["indicators"])

        # 3. Benign consistency: identical platform and fingerprint
        ev5 = {
            "session_id": "SES-PLAT-03",
            "timestamp": "2026-10-15T13:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "windows",
            "client_tls_fingerprint": "ja4_fingerprint_001",
        }
        ev6 = {
            "session_id": "SES-PLAT-03",
            "timestamp": "2026-10-15T13:02:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "windows",
            "client_tls_fingerprint": "ja4_fingerprint_001",
        }
        self.tracker.correlate_event(ev5)
        res6 = self.tracker.correlate_event(ev6)
        self.assertNotIn("CLIENT_PLATFORM_DIVERGENCE", res6["indicators"])

        # 4. Missing platform/fingerprint telemetry does not trigger false positive
        ev7 = {
            "session_id": "SES-PLAT-04",
            "timestamp": "2026-10-15T13:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
        }
        ev8 = {
            "session_id": "SES-PLAT-04",
            "timestamp": "2026-10-15T13:02:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "client_platform": "windows",
        }
        self.tracker.correlate_event(ev7)
        res8 = self.tracker.correlate_event(ev8)
        self.assertNotIn("CLIENT_PLATFORM_DIVERGENCE", res8["indicators"])

    def test_token_binding_failure(self):
        # 1. Initial event with token_binding_status: failed
        ev_init_fail = {
            "session_id": "SES-TB-01",
            "timestamp": "2026-10-15T14:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "token_binding_status": "failed",
        }
        res1 = self.tracker.correlate_event(ev_init_fail)
        self.assertIn("TOKEN_BINDING_FAILURE", res1["indicators"])

        # 2. Key mismatch status
        ev_mismatch = {
            "session_id": "SES-TB-02",
            "timestamp": "2026-10-15T14:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "token_binding_status": "key_mismatch",
        }
        res2 = self.tracker.correlate_event(ev_mismatch)
        self.assertIn("TOKEN_BINDING_FAILURE", res2["indicators"])

        # 3. Subsequent event failure
        ev_sub_ok = {
            "session_id": "SES-TB-03",
            "timestamp": "2026-10-15T14:00:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "token_binding_status": "valid",
        }
        ev_sub_fail = {
            "session_id": "SES-TB-03",
            "timestamp": "2026-10-15T14:02:00Z",
            "source_ip": "192.0.2.10",
            "device_id": "DEV-01",
            "token_binding_status": "failed",
        }
        r3_ok = self.tracker.correlate_event(ev_sub_ok)
        self.assertNotIn("TOKEN_BINDING_FAILURE", r3_ok["indicators"])
        r3_fail = self.tracker.correlate_event(ev_sub_fail)
        self.assertIn("TOKEN_BINDING_FAILURE", r3_fail["indicators"])

        # 4. Benign statuses: valid, supported, absent, unparseable
        for benign_status in ["valid", "supported", "UNKNOWN_STATUS", 12345, None]:
            ev_benign = {
                "session_id": f"SES-TB-BENIGN-{benign_status}",
                "timestamp": "2026-10-15T14:00:00Z",
                "source_ip": "192.0.2.10",
                "device_id": "DEV-01",
                "token_binding_status": benign_status,
            }
            res_benign = self.tracker.correlate_event(ev_benign)
            self.assertNotIn("TOKEN_BINDING_FAILURE", res_benign["indicators"])

    # -------------------------------------------------------------
    # 13. Regression Tests for Out-of-Order, Token Binding & Fingerprints
    # -------------------------------------------------------------
    def test_out_of_order_compares_against_chronological_predecessor_never_future(self):
        # Event 1: 12:00:00, DEV-A, 192.0.2.1
        ev1 = {
            "session_id": "SES-PRED-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }
        # Event 2: 12:10:00 (arrives 2nd), DEV-B, 198.51.100.9 (different device & IP in future)
        ev2 = {
            "session_id": "SES-PRED-01",
            "timestamp": "2026-10-15T12:10:00Z",
            "source_ip": "198.51.100.9",
            "device_id": "DEV-B",
        }
        # Event 3: 12:02:30 (arrives 3rd, out of order between ev1 and ev2), DEV-A, 192.0.2.1
        ev3 = {
            "session_id": "SES-PRED-01",
            "timestamp": "2026-10-15T12:02:30Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }

        self.tracker.correlate_event(ev1)
        self.tracker.correlate_event(ev2)
        res3 = self.tracker.correlate_event(ev3)

        # Must flag OUT_OF_ORDER_EVENT because it arrived out of chronological sequence
        self.assertIn("OUT_OF_ORDER_EVENT", res3["indicators"])
        # Crucial: Must correlate against chronological predecessor ev1 (DEV-A), NOT future ev2 (DEV-B)
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res3["indicators"])
        self.assertNotIn("BENIGN_IP_ROAMING_PLAUSIBLE", res3["indicators"])
        self.assertEqual(res3["context_details"]["prior_device"], "DEV-A")
        self.assertEqual(res3["context_details"]["current_device"], "DEV-A")
        self.assertEqual(res3["delta_seconds"], 150.0)
        self.assertGreaterEqual(res3["delta_seconds"], 0.0)
        self.assertNotIn("after -", res3["explanation"])
        self.assertNotIn("within -", res3["explanation"])

    def test_out_of_order_does_not_suppress_rapid_ip_change_from_predecessor(self):
        # Event 1: 12:00:00, DEV-A, 192.0.2.1
        ev1 = {
            "session_id": "SES-PRED-02",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }
        # Event 3: 12:10:00 (arrives 2nd), DEV-A, 192.0.2.1
        ev3 = {
            "session_id": "SES-PRED-02",
            "timestamp": "2026-10-15T12:10:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }
        # Event 2: 12:00:30 (arrives 3rd, 30s after ev1), DEV-A, 198.51.100.9 (IP changed rapidly)
        ev2 = {
            "session_id": "SES-PRED-02",
            "timestamp": "2026-10-15T12:00:30Z",
            "source_ip": "198.51.100.9",
            "device_id": "DEV-A",
        }

        self.tracker.correlate_event(ev1)
        self.tracker.correlate_event(ev3)
        res2 = self.tracker.correlate_event(ev2)

        # Anomaly occurred 30s after chronological predecessor ev1; must NOT be suppressed
        self.assertIn("OUT_OF_ORDER_EVENT", res2["indicators"])
        self.assertIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])
        self.assertEqual(res2["delta_seconds"], 30.0)
        self.assertIn("within 30.0s", res2["explanation"])

    def test_out_of_order_earliest_in_session_has_no_predecessor(self):
        # Event 2 arrives first: 12:10:00, DEV-B, 198.51.100.9
        ev2 = {
            "session_id": "SES-EARLY-01",
            "timestamp": "2026-10-15T12:10:00Z",
            "source_ip": "198.51.100.9",
            "device_id": "DEV-B",
        }
        # Event 1 arrives second: 12:00:00, DEV-A, 192.0.2.1 (earlier than all recorded events)
        ev1 = {
            "session_id": "SES-EARLY-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }

        self.tracker.correlate_event(ev2)
        res1 = self.tracker.correlate_event(ev1)

        self.assertIn("OUT_OF_ORDER_EVENT", res1["indicators"])
        # Must NOT compare against future ev2 (no false device or IP changes)
        self.assertNotIn("DEVICE_CONTEXT_CHANGED", res1["indicators"])
        self.assertNotIn("RAPID_SOURCE_IP_CHANGE", res1["indicators"])
        self.assertNotIn("BENIGN_IP_ROAMING_PLAUSIBLE", res1["indicators"])
        self.assertIsNone(res1["delta_seconds"])
        self.assertIsNone(res1["context_details"]["prior_device"])
        self.assertIsNone(res1["context_details"]["prior_ip"])

    def test_equal_timestamps_deterministic_elapsed_time(self):
        ev1 = {
            "session_id": "SES-EQ-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
        }
        ev2 = {
            "session_id": "SES-EQ-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "198.51.100.2",
            "device_id": "DEV-A",
        }
        self.tracker.correlate_event(ev1)
        res2 = self.tracker.correlate_event(ev2)

        self.assertNotIn("OUT_OF_ORDER_EVENT", res2["indicators"])
        self.assertIn("RAPID_SOURCE_IP_CHANGE", res2["indicators"])
        self.assertEqual(res2["delta_seconds"], 0.0)
        self.assertIn("within 0.0s", res2["explanation"])
        self.assertNotIn("after -", res2["explanation"])
        self.assertNotIn("within -", res2["explanation"])

    def test_token_binding_failure_retained_on_missing_or_invalid_timestamp(self):
        # 1. Missing timestamp with token binding failure
        ev_missing = {
            "session_id": "SES-TB-TS-01",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
            "token_binding_status": "failed",
        }
        res_missing = self.tracker.correlate_event(ev_missing)
        self.assertIn("MISSING_TIMESTAMP", res_missing["indicators"])
        self.assertIn("TOKEN_BINDING_FAILURE", res_missing["indicators"])
        self.assertFalse(res_missing["is_correlated"])
        self.assertEqual(res_missing["context_details"]["token_binding_status"], "failed")

        # 2. Invalid timestamp with token binding key mismatch
        ev_invalid = {
            "session_id": "SES-TB-TS-02",
            "timestamp": "malformed-not-a-timestamp",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
            "token_binding_status": "key_mismatch",
        }
        res_invalid = self.tracker.correlate_event(ev_invalid)
        self.assertIn("INVALID_TIMESTAMP", res_invalid["indicators"])
        self.assertIn("TOKEN_BINDING_FAILURE", res_invalid["indicators"])
        self.assertFalse(res_invalid["is_correlated"])
        self.assertEqual(res_invalid["context_details"]["token_binding_status"], "key_mismatch")

        # 3. Benign counterexample: missing timestamp with valid status
        ev_benign = {
            "session_id": "SES-TB-TS-03",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
            "token_binding_status": "valid",
        }
        res_benign = self.tracker.correlate_event(ev_benign)
        self.assertIn("MISSING_TIMESTAMP", res_benign["indicators"])
        self.assertNotIn("TOKEN_BINDING_FAILURE", res_benign["indicators"])

    def test_tls_fingerprint_whitespace_normalization_and_context_details(self):
        ev1 = {
            "session_id": "SES-FP-NORM-01",
            "timestamp": "2026-10-15T12:00:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
            "client_tls_fingerprint": "  ja4_fingerprint_001 \t ",
        }
        ev2 = {
            "session_id": "SES-FP-NORM-01",
            "timestamp": "2026-10-15T12:02:00Z",
            "source_ip": "192.0.2.1",
            "device_id": "DEV-A",
            "client_tls_fingerprint": "ja4_fingerprint_001",
        }
        res1 = self.tracker.correlate_event(ev1)
        self.assertEqual(res1["context_details"]["client_tls_fingerprint"], "ja4_fingerprint_001")

        res2 = self.tracker.correlate_event(ev2)
        # Stripped values match, so no divergence
        self.assertNotIn("CLIENT_PLATFORM_DIVERGENCE", res2["indicators"])
        self.assertEqual(res2["context_details"]["prior_tls_fingerprint"], "ja4_fingerprint_001")
        self.assertEqual(res2["context_details"]["current_tls_fingerprint"], "ja4_fingerprint_001")


if __name__ == "__main__":
    unittest.main()
