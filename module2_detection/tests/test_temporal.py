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


if __name__ == "__main__":
    unittest.main()
