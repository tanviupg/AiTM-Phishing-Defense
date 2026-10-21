"""
Unit tests for IdP Audit Log Adapter (Real-World Read-Only Integration).
Verifies ingestion and normalization of enterprise audit logs (Entra ID, Okta).
"""

import unittest
from pathlib import Path
from module2_detection.audit_log_adapter import IdPAuditLogAdapter

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "sample_idp_audit_logs"


class TestIdPAuditLogAdapter(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = IdPAuditLogAdapter()

    def test_parse_entra_id_benign_record(self) -> None:
        record = {
            "id": "test-benign-1",
            "createdDateTime": "2026-10-21T10:00:00Z",
            "userPrincipalName": "alice@contoso.com",
            "ipAddress": "198.51.100.10",
            "status": {"errorCode": 0},
            "deviceDetail": {"deviceId": "DEV-01", "operatingSystem": "Windows 11", "isCompliant": True},
            "tokenBindingStatus": "valid",
        }
        event = self.adapter.parse_entra_id_log(record)
        self.assertEqual(event["session_id"], "test-benign-1")
        self.assertEqual(event["auth_result"], "success")
        self.assertFalse(event["tls_anomaly"])
        self.assertFalse(event["replay_indicator"])

    def test_ingest_and_evaluate_entra_id_sample_file(self) -> None:
        sample_file = DATA_DIR / "entra_id_audit_sample.json"
        self.assertTrue(sample_file.exists())

        results = self.adapter.evaluate_audit_log_file(sample_file)
        self.assertEqual(len(results), 2)

        # First entry is benign
        benign_res = results[0]["detection"]
        self.assertEqual(benign_res["composite_verdict"], "benign")

        # Second entry has proxy redirect loop and token binding failure -> flagged as suspicious!
        susp_res = results[1]["detection"]
        self.assertEqual(susp_res["composite_verdict"], "suspicious")
        self.assertGreaterEqual(susp_res["composite_risk_score"], 0.50)


if __name__ == "__main__":
    unittest.main()
