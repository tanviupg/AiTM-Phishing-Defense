"""
Analytics & Threat Aggregation Service for Module 4 SOC Dashboard.

Transforms real detection telemetry from Module 2 and incident/session records
from Module 3 into overview KPIs, threat indicator breakdowns, and chart datasets.
"""

from collections import defaultdict
from typing import Any

from module4_soc_dashboard.backend.integration_service import ModuleIntegrationService


class AnalyticsService:
    """Computes SOC overview metrics, threat indicators, and chart series."""

    def __init__(self, integration: ModuleIntegrationService) -> None:
        self.integration = integration

    def get_dashboard_overview(self) -> dict[str, Any]:
        """Returns overview KPI cards, threat analysis indicators, and all chart datasets."""
        events_res = self.integration.get_events(limit=500)
        incidents_res = self.integration.get_incidents()
        sessions_res = self.integration.get_sessions()

        events = events_res["items"]
        incidents = incidents_res["items"]
        sessions = sessions_res["items"]

        is_mock = bool(
            events_res.get("is_mock_data")
            or incidents_res.get("is_mock_data")
            or sessions_res.get("is_mock_data")
        )
        data_source = events_res.get("data_source", "DIRECT_PIPELINE")

        # Count incidents by risk tier
        high_risk_incidents = sum(
            1 for i in incidents if str(i.get("severity", "")).lower() in ("high", "critical")
        )
        medium_risk_incidents = sum(
            1 for i in incidents if str(i.get("severity", "")).lower() == "medium"
        )
        low_risk_incidents = sum(
            1 for i in incidents if str(i.get("severity", "")).lower() == "low"
        )

        # Count low-risk monitored events if no low-risk incidents exist so analysts see baseline counts too
        low_risk_events = sum(
            1 for e in events if str(e.get("severity", "")).lower() == "low"
        )

        total_phishing_alerts = sum(
            1 for e in events if str(e.get("severity", "")).lower() in ("medium", "high", "critical")
        )
        suspicious_sessions = sum(
            1
            for s in sessions
            if bool(s.get("replay_indicator")) or s.get("status") == "revoked"
            or any(
                i.get("session_id") == s.get("session_id")
                and str(i.get("severity", "")).lower() in ("medium", "high", "critical")
                for i in incidents
            )
        )
        revoked_sessions = sum(1 for s in sessions if s.get("status") == "revoked")

        # Threat Analysis indicator extraction
        tls_anomalies: list[dict[str, Any]] = []
        redirect_anomalies: list[dict[str, Any]] = []
        session_anomalies: list[dict[str, Any]] = []
        replay_indicators: list[dict[str, Any]] = []

        for ev in events:
            inds = ev.get("triggered_indicators") or []
            sid = ev.get("session_id", "UNKNOWN")
            ts = ev.get("timestamp", "")
            reason = ev.get("detection_reason", "")

            has_tls = bool(ev.get("tls_anomaly")) or any(
                i.startswith("tls:") and i != "tls:UNOBSERVED_TLS_TELEMETRY" for i in inds
            )
            if has_tls:
                tls_anomalies.append({
                    "event_id": ev["event_id"],
                    "session_id": sid,
                    "timestamp": ts,
                    "indicators": [i for i in inds if i.startswith("tls:") or "TLS" in i],
                    "reason": reason,
                })

            has_redirect = int(ev.get("redirect_count", 0)) > 3 or any(
                i.startswith("base:") and ("REDIRECT" in i or "COMPLEXITY" in i) for i in inds
            )
            if has_redirect:
                redirect_anomalies.append({
                    "event_id": ev["event_id"],
                    "session_id": sid,
                    "timestamp": ts,
                    "redirect_count": ev.get("redirect_count", 0),
                    "redirect_chain": ev.get("redirect_chain", []),
                    "indicators": [i for i in inds if i.startswith("base:")],
                    "reason": reason,
                })

            has_session_anom = any(
                i in inds
                for i in (
                    "session:SUSPICIOUS_CONTEXT_MISMATCH",
                    "session:CLIENT_PLATFORM_DIVERGENCE",
                    "session:DEVICE_CONTEXT_CHANGED",
                    "session:RAPID_SOURCE_IP_CHANGE",
                    "session:DATACENTER_SOURCE_TRANSITION",
                )
            ) or any(
                i.get("session_id") == sid and i.get("signals", {}).get("context_anomaly")
                for i in incidents
            )
            if has_session_anom:
                session_anomalies.append({
                    "event_id": ev["event_id"],
                    "session_id": sid,
                    "timestamp": ts,
                    "source_ip": ev.get("source_ip", ""),
                    "device_id": ev.get("device_id", ""),
                    "reason": reason,
                })

            has_replay = bool(ev.get("replay_indicator")) or any(
                i in inds
                for i in (
                    "session:TOKEN_BINDING_FAILURE",
                    "session:CONCURRENT_SESSION_BIFURCATION",
                )
            )
            if has_replay:
                replay_indicators.append({
                    "event_id": ev["event_id"],
                    "session_id": sid,
                    "timestamp": ts,
                    "indicators": [i for i in inds if "TOKEN" in i or "BIFURCATION" in i] or ["SIMULATED_TOKEN_REPLAY"],
                    "reason": reason,
                })

        # Charts
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for ev in events:
            sev = str(ev.get("severity", "Low")).capitalize()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["Low"] += 1

        risk_buckets = {
            "0-29 (Low)": 0,
            "30-59 (Medium)": 0,
            "60-79 (High)": 0,
            "80-100 (Critical)": 0,
        }
        for ev in events:
            score = int(ev.get("risk_score", 0))
            if score >= 80:
                risk_buckets["80-100 (Critical)"] += 1
            elif score >= 60:
                risk_buckets["60-79 (High)"] += 1
            elif score >= 30:
                risk_buckets["30-59 (Medium)"] += 1
            else:
                risk_buckets["0-29 (Low)"] += 1

        # Time-series aggregation
        timeline_buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "alerts": 0})
        for ev in sorted(events, key=lambda x: str(x.get("timestamp", ""))):
            ts = str(ev.get("timestamp", ""))
            label = ts[:16].replace("T", " ") if len(ts) >= 16 else (ts or "Unknown")
            timeline_buckets[label]["total"] += 1
            if str(ev.get("severity", "")).lower() in ("medium", "high", "critical"):
                timeline_buckets[label]["alerts"] += 1

        events_over_time = [
            {"label": k, "total_events": v["total"], "phishing_alerts": v["alerts"]}
            for k, v in list(timeline_buckets.items())[-12:]
        ]

        detection_categories = [
            {"category": "TLS / Certificate", "count": len(tls_anomalies)},
            {"category": "Redirect Chains", "count": len(redirect_anomalies)},
            {"category": "Token Replay", "count": len(replay_indicators)},
            {"category": "Session Context", "count": len(session_anomalies)},
        ]

        incident_status_counts = {"Open": 0, "Investigating": 0, "Contained": 0, "Resolved": 0}
        for inc in incidents:
            st = inc.get("status", "Open")
            if st in incident_status_counts:
                incident_status_counts[st] += 1
            else:
                incident_status_counts["Open"] += 1

        return {
            "data_source": data_source,
            "is_mock_data": is_mock,
            "overview": {
                "total_events": len(events),
                "total_phishing_alerts": total_phishing_alerts,
                "high_risk_incidents": high_risk_incidents,
                "medium_risk_incidents": medium_risk_incidents,
                "low_risk_incidents": low_risk_incidents,
                "low_risk_events": low_risk_events,
                "suspicious_sessions": suspicious_sessions,
                "revoked_sessions": revoked_sessions,
                "total_incidents": len(incidents),
            },
            "threat_analysis": {
                "tls_certificate_anomalies": {
                    "count": len(tls_anomalies),
                    "items": tls_anomalies,
                },
                "suspicious_redirect_chains": {
                    "count": len(redirect_anomalies),
                    "items": redirect_anomalies,
                },
                "session_anomalies": {
                    "count": len(session_anomalies),
                    "items": session_anomalies,
                },
                "token_replay_indicators": {
                    "count": len(replay_indicators),
                    "items": replay_indicators,
                },
            },
            "charts": {
                "severity_distribution": [
                    {"label": k, "value": v} for k, v in severity_counts.items()
                ],
                "risk_score_distribution": [
                    {"label": k, "value": v} for k, v in risk_buckets.items()
                ],
                "events_over_time": events_over_time,
                "detection_category_distribution": detection_categories,
                "incident_statistics": [
                    {"label": k, "value": v} for k, v in incident_status_counts.items()
                ],
            },
            "recent_incidents": incidents[:6],
        }
