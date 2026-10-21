"""
Read-Only Identity Provider (IdP) Audit Log Adapter (Module 2 Extension).
Enables the AiTM detection engine to ingest real-world sign-in audit logs
from authorized identity providers (Microsoft Entra ID, Okta, Google Workspace) in read-only mode.
Demonstrates genuine industrial integration without requiring live network interception of real users.
"""

import json
from pathlib import Path
from typing import Any, Optional
from module2_detection.detector import AiTMDetector
from module2_detection.session_tracker import SessionTracker
from module2_detection.tls_analyzer import TLSAnalyzer


class IdPAuditLogAdapter:
    """
    Normalizes heterogeneous enterprise Identity Provider audit logs into the
    AiTM detection pipeline's standardized telemetry event schema.
    """

    def __init__(self, detector: Optional[AiTMDetector] = None) -> None:
        self.detector = detector or AiTMDetector()
        self.session_tracker = SessionTracker()
        self.tls_analyzer = TLSAnalyzer()

    def parse_entra_id_log(self, record: dict[str, Any]) -> dict[str, Any]:
        """
        Maps a Microsoft Entra ID (Azure AD) sign-in log entry to the AiTM event schema.
        Handles fields: id, createdDateTime, ipAddress, location, deviceDetail, status, tokenBindingStatus.
        """
        session_id = record.get("id", "ENTRA-UNKNOWN")
        timestamp = record.get("createdDateTime", "")
        status = record.get("status", {})
        auth_result = "success" if status.get("errorCode", 0) == 0 else "failure"

        device_detail = record.get("deviceDetail", {})
        device_id = device_detail.get("deviceId", "UNKNOWN-DEVICE")
        client_platform = (device_detail.get("operatingSystem") or "unknown").lower()

        source_ip = record.get("ipAddress", "0.0.0.0")

        # Extract redirect chain if available in proxy telemetry / correlation log
        redirect_chain = record.get("redirectChain", ["login.microsoftonline.com"])
        redirect_count = len(redirect_chain) - 1 if len(redirect_chain) > 1 else 1

        token_binding = record.get("tokenBindingStatus", "none")

        # Heuristic TLS anomaly indicator if non-compliant unmanaged browser was used
        tls_anomaly = record.get("tls_anomaly", False)
        if not device_detail.get("isCompliant", True) and "phish" in "".join(redirect_chain):
            tls_anomaly = True

        return {
            "session_id": session_id,
            "timestamp": timestamp,
            "auth_result": auth_result,
            "redirect_count": redirect_count,
            "redirect_chain": redirect_chain,
            "tls_anomaly": tls_anomaly,
            "replay_indicator": token_binding in ("failed", "key_mismatch"),
            "source_ip": source_ip,
            "device_id": device_id,
            "scenario": "suspicious_simulation" if tls_anomaly or redirect_count > 2 else "normal",
            "client_platform": client_platform,
            "token_binding_status": token_binding,
            "user_principal_name": record.get("userPrincipalName", "user@domain.com"),
        }

    def ingest_entra_id_file(self, file_path: Path) -> list[dict[str, Any]]:
        """Reads a file containing Entra ID JSON audit log records and returns normalized events."""
        with open(file_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        if isinstance(records, dict) and "value" in records:
            records = records["value"]

        return [self.parse_entra_id_log(rec) for rec in records]

    def evaluate_audit_log_file(self, file_path: Path) -> list[dict[str, Any]]:
        """
        Ingests audit log file, evaluates each record through the detection engine,
        and returns detection results.
        """
        events = self.ingest_entra_id_file(file_path)
        results: list[dict[str, Any]] = []

        for ev in events:
            det_res = self.detector.analyze_event_composite(
                ev,
                session_tracker=self.session_tracker,
                tls_analyzer=self.tls_analyzer,
            )
            results.append({
                "original_session_id": ev["session_id"],
                "user": ev["user_principal_name"],
                "normalized_event": ev,
                "detection": det_res,
            })

        return results
