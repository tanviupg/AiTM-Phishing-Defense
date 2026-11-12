"""
Integration & Service Layer connecting Module 4 (SOC Dashboard) with:
- Module 1: module1_aitm_poc (session events, sample_events.json, live_intercepted_event.json)
- Module 2: module2_detection (AiTMDetector, SessionTracker, TLSAnalyzer)
- Module 3: module3_hardening (HardeningEngine, HardeningChecklist, AuthDefenseKnowledgeBase,
            SQLite store, lab_scenarios, and optional REST API on port 8000)

Never invents endpoints or duplicates detection algorithms.
Clearly distinguishes live/direct pipeline telemetry from synthetic fallback data.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from module4_soc_dashboard.backend.mock_fallback import (
    FALLBACK_EVENTS,
    FALLBACK_INCIDENTS,
    FALLBACK_SESSIONS,
)

# Optional imports of existing team modules (never modified)
try:
    from module1_aitm_poc.event_generator import validate_event as m1_validate_event
    MODULE1_AVAILABLE = True
except ImportError:
    MODULE1_AVAILABLE = False
    m1_validate_event = None

try:
    from integration.run_pipeline import validate_against_schema as integration_validate_event
    SCHEMA_FILE = ROOT_DIR / "integration" / "event_schema.json"
    INTEGRATION_SCHEMA_AVAILABLE = SCHEMA_FILE.exists()
except ImportError:
    INTEGRATION_SCHEMA_AVAILABLE = False
    integration_validate_event = None
    SCHEMA_FILE = ROOT_DIR / "integration" / "event_schema.json"

try:
    from module2_detection.detector import AiTMDetector
    from module2_detection.session_tracker import SessionTracker
    from module2_detection.tls_analyzer import TLSAnalyzer
    MODULE2_AVAILABLE = True
except ImportError:
    MODULE2_AVAILABLE = False
    AiTMDetector = None
    SessionTracker = None
    TLSAnalyzer = None

try:
    from module3_hardening.auth_defense import AuthDefenseKnowledgeBase
    from module3_hardening.database import (
        get_db_connection,
        init_db,
        record_event,
        record_incident,
        record_session,
        reset_test_data,
        revoke_session_db,
        verify_session_access,
    )
    from module3_hardening.hardening_checklist import HardeningChecklist
    from module3_hardening.lab_scenarios import LAB_SCENARIOS, list_scenarios, run_lab_scenario
    from module3_hardening.recommendation_engine import HardeningEngine
    MODULE3_AVAILABLE = True
except ImportError:
    MODULE3_AVAILABLE = False


def sanitize_event_telemetry(event: dict[str, Any]) -> dict[str, Any]:
    """
    Safety guard: removes or redacts any raw token/credential fields before
    persisting or returning telemetry to the SOC UI.
    """
    cleaned = dict(event)
    for sensitive_key in ("stolen_token", "session_token", "password", "cookie", "raw_cookie"):
        if sensitive_key in cleaned:
            cleaned[sensitive_key] = "[REDACTED_SYNTHETIC_LAB_VALUE]"
    return cleaned


class ModuleIntegrationService:
    """
    Unified adapter connecting Module 4 to Modules 1, 2, and 3.

    Precedence:
    1. LIVE_MODULE3_API: When `AITM_API_BASE_URL` is configured (or reachable when
       `prefer_live_api=True`) and responds healthy.
    2. DIRECT_PIPELINE: Uses direct Python imports of Modules 1, 2, and 3 plus
       the shared SQLite store (`data/aitm_sentinel.db`).
    3. SYNTHETIC_FALLBACK: Only when Modules 1-3 and the API are unavailable.
    """

    def __init__(
        self,
        api_base_url: Optional[str] = None,
        prefer_live_api: bool = False,
        force_fallback: bool = False,
    ) -> None:
        self.api_base_url = (
            api_base_url
            or os.environ.get("AITM_API_BASE_URL", "http://127.0.0.1:8000")
        ).rstrip("/")
        self.prefer_live_api = prefer_live_api or bool(os.environ.get("AITM_API_BASE_URL"))
        self.force_fallback = force_fallback

        self._detector = AiTMDetector() if MODULE2_AVAILABLE else None
        self._session_tracker = SessionTracker() if MODULE2_AVAILABLE else None
        self._tls_analyzer = TLSAnalyzer() if MODULE2_AVAILABLE else None
        self._hardening_engine = HardeningEngine() if MODULE3_AVAILABLE else None
        self._hardening_checklist = HardeningChecklist() if MODULE3_AVAILABLE else None
        self._auth_kb = AuthDefenseKnowledgeBase() if MODULE3_AVAILABLE else None

        # Deep copy fallback state for isolated mock fallback operations
        self._fallback_events = [dict(e) for e in FALLBACK_EVENTS]
        self._fallback_incidents = [dict(i) for i in FALLBACK_INCIDENTS]
        self._fallback_sessions = [dict(s) for s in FALLBACK_SESSIONS]

        if MODULE3_AVAILABLE and not self.force_fallback:
            init_db()

    # ------------------------------------------------------------------
    # Connectivity & Source Provenance
    # ------------------------------------------------------------------

    def _probe_live_api(self) -> Optional[dict[str, Any]]:
        """Checks if Module 3's FastAPI server is reachable at `api_base_url`."""
        if self.force_fallback:
            return None
        url = f"{self.api_base_url}/api/defense/health"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=0.6) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        return None

    def _api_request(
        self,
        path: str,
        method: str = "GET",
        payload: Optional[dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.api_base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            raw = resp.read().decode("utf-8")
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                return json.loads(raw)
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw

    def get_active_mode(self) -> str:
        if self.force_fallback:
            return "SYNTHETIC_FALLBACK"
        if self.prefer_live_api and self._probe_live_api() is not None:
            return "LIVE_MODULE3_API"
        if MODULE2_AVAILABLE and MODULE3_AVAILABLE:
            return "DIRECT_PIPELINE"
        if self._probe_live_api() is not None:
            return "LIVE_MODULE3_API"
        return "SYNTHETIC_FALLBACK"

    def get_system_status(self) -> dict[str, Any]:
        """Reports live health and integration provenance across Modules 1, 2, 3, and 4."""
        live_health = None if self.force_fallback else self._probe_live_api()
        mode = self.get_active_mode()
        is_mock = mode == "SYNTHETIC_FALLBACK"

        sample_file = ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"
        live_file = ROOT_DIR / "module1_aitm_poc" / "events" / "live_intercepted_event.json"

        return {
            "status": "degraded_fallback" if is_mock else "operational",
            "integration_mode": mode,
            "is_mock_data": is_mock,
            "data_source_label": (
                "Synthetic Demonstration Fallback (Live Modules Unavailable)"
                if is_mock
                else (
                    f"Live Module 3 REST API ({self.api_base_url})"
                    if mode == "LIVE_MODULE3_API"
                    else "Direct Python Pipeline (Modules 1 -> 2 -> 3 + SQLite)"
                )
            ),
            "modules": {
                "module1_event_generator": {
                    "available": MODULE1_AVAILABLE and not self.force_fallback,
                    "sample_events_present": sample_file.exists(),
                    "live_proxy_event_present": live_file.exists(),
                },
                "module2_detection_engine": {
                    "available": MODULE2_AVAILABLE and not self.force_fallback,
                    "formula": "R = 30D + 20C + 25S + 15E + 10A",
                },
                "module3_hardening_api": {
                    "available": MODULE3_AVAILABLE and not self.force_fallback,
                    "rest_api_reachable": live_health is not None,
                    "rest_api_url": self.api_base_url,
                },
                "module4_soc_dashboard": {
                    "available": True,
                    "version": "1.0.0",
                },
            },
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Module 1 -> Module 2 -> Module 3 Ingestion
    # ------------------------------------------------------------------

    def load_module1_events(self) -> list[dict[str, Any]]:
        """Reads synthetic events produced by Module 1 (sample + live proxy capture if present)."""
        events: list[dict[str, Any]] = []
        sample_file = ROOT_DIR / "module1_aitm_poc" / "events" / "sample_events.json"
        live_file = ROOT_DIR / "module1_aitm_poc" / "events" / "live_intercepted_event.json"

        if sample_file.exists():
            with sample_file.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    events.extend(loaded)

        if live_file.exists():
            with live_file.open("r", encoding="utf-8") as f:
                live_ev = json.load(f)
                if isinstance(live_ev, dict):
                    events.append(live_ev)

        return [sanitize_event_telemetry(e) for e in events]

    def _validate_module1_event(self, event: dict[str, Any]) -> None:
        if INTEGRATION_SCHEMA_AVAILABLE and integration_validate_event is not None:
            with SCHEMA_FILE.open("r", encoding="utf-8") as f:
                schema = json.load(f)
            if event.get("scenario") in schema.get("scenarios", []):
                integration_validate_event(event, schema)
                return
        if MODULE1_AVAILABLE and m1_validate_event is not None:
            m1_validate_event(event)

    def _compute_formula_breakdown(
        self,
        event: dict[str, Any],
        detection: dict[str, Any],
    ) -> dict[str, Any]:
        """Computes R = 30D + 20C + 25S + 15E + 10A consistently with Module 3 lab_scenarios."""
        indicators = set(detection.get("all_triggered_indicators", []))
        chain = event.get("redirect_chain", [])
        dest = str(event.get("destination_host", "") or "")

        d_sig = 1 if (
            any(tok in dest for tok in ("corp-auth-check.invalid", "reverse-proxy", "auth-relay"))
            or any(".invalid" in h or "proxy" in h for h in chain)
        ) else 0

        c_sig = 1 if (
            bool(event.get("tls_anomaly"))
            or "tls:CERT_HOSTNAME_MISMATCH" in indicators
            or "tls:UNTRUSTED_SELF_SIGNED_CERT" in indicators
            or "tls:LEGACY_TLS_ANOMALY_FLAG" in indicators
        ) else 0

        s_sig = 1 if (
            bool(event.get("replay_indicator"))
            or "session:TOKEN_BINDING_FAILURE" in indicators
            or "session:CONCURRENT_SESSION_BIFURCATION" in indicators
        ) else 0

        e_sig = 1 if (
            int(event.get("redirect_count", 0)) > 3
            or "base:SUSPICIOUS_REDIRECT_CYCLE" in indicators
            or "base:HIGH_TRANSITION_COMPLEXITY" in indicators
        ) else 0

        a_sig = 1 if (
            "session:SUSPICIOUS_CONTEXT_MISMATCH" in indicators
            or "session:CLIENT_PLATFORM_DIVERGENCE" in indicators
            or "session:DEVICE_CONTEXT_CHANGED" in indicators
            or "session:RAPID_SOURCE_IP_CHANGE" in indicators
        ) else 0

        formula_r = (30 * d_sig) + (20 * c_sig) + (25 * s_sig) + (15 * e_sig) + (10 * a_sig)
        # Ensure consistency with Module 2 composite_risk_score when formula_r is 0 but composite > 0
        composite_pct = int(round(float(detection.get("composite_risk_score", 0.0)) * 100))
        final_score = max(formula_r, composite_pct) if formula_r > 0 else composite_pct

        return {
            "formula": "R = 30D + 20C + 25S + 15E + 10A",
            "variables": {"D": d_sig, "C": c_sig, "S": s_sig, "E": e_sig, "A": a_sig},
            "weights": {"D": 30, "C": 20, "S": 25, "E": 15, "A": 10},
            "contributions": {
                "D": 30 * d_sig,
                "C": 20 * c_sig,
                "S": 25 * s_sig,
                "E": 15 * e_sig,
                "A": 10 * a_sig,
            },
            "score_out_of_100": min(final_score, 100),
            "investigation_threshold": 60,
            "requires_investigation": final_score >= 60,
        }

    def analyze_and_ingest_event(self, raw_event: dict[str, Any], persist: bool = True) -> dict[str, Any]:
        """
        Runs a single synthetic event through Module 1 validation, Module 2 composite
        detection, and Module 3 hardening/persistence.
        """
        event = sanitize_event_telemetry(raw_event)
        if not event.get("timestamp"):
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK" or not (MODULE2_AVAILABLE and MODULE3_AVAILABLE):
            raise RuntimeError("Direct Module 2/3 pipeline unavailable in fallback mode.")

        self._validate_module1_event(event)

        detection = self._detector.analyze_event_composite(
            event,
            session_tracker=self._session_tracker,
            tls_analyzer=self._tls_analyzer,
        )
        formula = self._compute_formula_breakdown(event, detection)
        score_100 = formula["score_out_of_100"]

        if score_100 >= 60 or detection.get("composite_verdict") == "suspicious" and score_100 >= 50:
            risk_level = "HIGH"
            severity = "High"
        elif score_100 >= 30:
            risk_level = "MEDIUM"
            severity = "Medium"
        else:
            risk_level = "LOW"
            severity = "Low"

        detection_payload = {
            "session_id": event["session_id"],
            "risk_level": risk_level,
            "risk_score": round(score_100 / 100.0, 2),
            "signals": {
                "unexpected_domain": bool(formula["variables"]["D"]),
                "tls_anomaly": bool(formula["variables"]["C"]),
                "replay_indicator": bool(formula["variables"]["S"]),
                "redirect_anomaly": bool(formula["variables"]["E"]),
                "context_anomaly": bool(formula["variables"]["A"]),
            },
            "all_triggered_indicators": detection.get("all_triggered_indicators", []),
        }
        plan = self._hardening_engine.evaluate_detection(detection_payload)

        if persist:
            event_to_store = dict(event)
            event_to_store.setdefault("event_id", f"EVT-{event['session_id']}")
            event_to_store.setdefault("user_alias", event.get("device_id", "lab-user"))
            record_event(event_to_store, severity=severity)
            record_session(
                session_id=event["session_id"],
                user_alias=event_to_store["user_alias"],
                client_context=event.get("user_agent", event.get("device_id", "Lab-Client")),
                source_ip=event.get("source_ip", "192.0.2.1"),
                scenario=event.get("scenario", "normal"),
                replay_indicator=bool(event.get("replay_indicator", False)),
            )

            if risk_level in ("HIGH", "MEDIUM"):
                record_incident({
                    "incident_id": f"INC-{event['session_id']}",
                    "session_id": event["session_id"],
                    "title": f"AiTM Detection Alert ({event.get('scenario', 'event')})",
                    "severity": severity,
                    "risk_score": score_100,
                    "risk_level": risk_level,
                    "status": "Open",
                    "user_alias": event_to_store["user_alias"],
                    "scenario": event.get("scenario", "normal"),
                    "signals": detection_payload["signals"],
                    "formula_breakdown": formula,
                    "recommendations": plan.primary_recommendations,
                })

        return {
            "event": event,
            "detection": detection,
            "formula_breakdown": formula,
            "risk_level": risk_level,
            "severity": severity,
            "defense_plan": plan.to_dict(),
            "data_source": mode,
            "is_mock_data": False,
        }

    def ingest_module1_samples(self) -> dict[str, Any]:
        """Ingests Module 1 sample & live events through Module 2 and Module 3."""
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            return {
                "ingested_count": 0,
                "results": [],
                "data_source": "SYNTHETIC_FALLBACK",
                "is_mock_data": True,
                "message": "Pipeline unavailable; cannot ingest live Module 1 events.",
            }

        events = self.load_module1_events()
        results = []
        for ev in events:
            if mode == "LIVE_MODULE3_API":
                try:
                    res = self._api_request("/api/pipeline/evaluate", method="POST", payload=ev)
                    results.append(res)
                    continue
                except Exception:
                    pass
            if MODULE2_AVAILABLE and MODULE3_AVAILABLE:
                results.append(self.analyze_and_ingest_event(ev, persist=True))

        return {
            "ingested_count": len(results),
            "results": results,
            "data_source": mode,
            "is_mock_data": False,
        }

    def ensure_baseline_ingested(self) -> None:
        """
        If SQLite has no events yet in DIRECT_PIPELINE mode, automatically ingest
        Module 1's sample_events.json through Module 2 so the SOC dashboard immediately
        shows authentic Module 1 -> Module 2 -> Module 3 telemetry instead of an empty screen.
        """
        if self.force_fallback or not (MODULE2_AVAILABLE and MODULE3_AVAILABLE):
            return
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as cnt FROM events")
        cnt = c.fetchone()["cnt"]
        conn.close()
        if cnt == 0:
            self.ingest_module1_samples()

    # ------------------------------------------------------------------
    # Events, Incidents, Sessions & Lab Scenarios
    # ------------------------------------------------------------------

    def _enrich_event_row(
        self,
        row_dict: dict[str, Any],
        incidents_by_session: dict[str, dict[str, Any]],
        mode: str,
    ) -> dict[str, Any]:
        """Enriches an SQLite event row with Module 2 risk score, detection reason, and incident status."""
        raw_json = row_dict.get("raw_json")
        if isinstance(raw_json, str):
            raw_json = json.loads(raw_json) if raw_json else {}
        elif not isinstance(raw_json, dict):
            raw_json = {}

        redirect_chain = row_dict.get("redirect_chain")
        if isinstance(redirect_chain, str):
            redirect_chain = json.loads(redirect_chain) if redirect_chain else []
        elif not isinstance(redirect_chain, list):
            redirect_chain = []

        event_payload = {
            "session_id": row_dict.get("session_id", "UNKNOWN"),
            "timestamp": row_dict.get("timestamp", ""),
            "auth_result": row_dict.get("auth_result", "success"),
            "redirect_count": int(row_dict.get("redirect_count", 0)),
            "redirect_chain": redirect_chain,
            "tls_anomaly": bool(row_dict.get("tls_anomaly", False)),
            "replay_indicator": bool(row_dict.get("replay_indicator", False)),
            "source_ip": row_dict.get("source_ip", ""),
            "device_id": row_dict.get("device_id", ""),
            "scenario": row_dict.get("scenario", "normal"),
        }
        if "certificate_telemetry" in raw_json:
            event_payload["certificate_telemetry"] = raw_json["certificate_telemetry"]
        if "token_binding_status" in raw_json:
            event_payload["token_binding_status"] = raw_json["token_binding_status"]
        if "destination_host" in raw_json:
            event_payload["destination_host"] = raw_json["destination_host"]

        det_res: dict[str, Any] = {}
        if MODULE2_AVAILABLE and self._detector is not None:
            # Stateless read evaluation so GET requests don't mutate SessionTracker state
            det_res = self._detector.analyze_event_composite(
                event_payload,
                session_tracker=None,
                tls_analyzer=self._tls_analyzer,
            )

        linked_incident = incidents_by_session.get(event_payload["session_id"])
        if linked_incident:
            risk_score = int(linked_incident.get("risk_score", 0))
            incident_status = linked_incident.get("status", "Open")
            severity = linked_incident.get("severity", row_dict.get("severity", "Low"))
        else:
            risk_score = int(round(float(det_res.get("composite_risk_score", 0.0)) * 100))
            incident_status = "Monitored"
            severity = row_dict.get("severity", "Low")

        reason = det_res.get("composite_explanation") or (
            "No suspicious redirect, TLS, or replay indicators detected"
            if severity == "Low"
            else "Multi-signal AiTM heuristic alert"
        )

        return {
            "event_id": row_dict.get("event_id", f"EVT-{event_payload['session_id']}"),
            "timestamp": row_dict.get("timestamp", ""),
            "session_id": event_payload["session_id"],
            "user_alias": row_dict.get("user_alias", event_payload["device_id"]),
            "scenario": event_payload["scenario"],
            "source_ip": event_payload["source_ip"],
            "device_id": event_payload["device_id"],
            "redirect_count": event_payload["redirect_count"],
            "redirect_chain": redirect_chain,
            "tls_anomaly": event_payload["tls_anomaly"],
            "replay_indicator": event_payload["replay_indicator"],
            "risk_score": risk_score,
            "risk_score_normalized": round(risk_score / 100.0, 2),
            "severity": severity,
            "detection_reason": reason,
            "incident_status": incident_status,
            "incident_id": linked_incident.get("incident_id") if linked_incident else None,
            "triggered_indicators": det_res.get("all_triggered_indicators", []),
            "tls_analysis": det_res.get("tls_analysis"),
            "raw_json": sanitize_event_telemetry(raw_json),
            "is_mock_data": False,
            "data_source": mode,
        }

    def get_events(
        self,
        severity: Optional[str] = None,
        incident_status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            events = list(self._fallback_events)
            events = self._filter_event_list(events, severity, incident_status, search)[:limit]
            return {"items": events, "data_source": mode, "is_mock_data": True}

        self.ensure_baseline_ingested()
        incidents_res = self.get_incidents()
        incidents_by_session = {
            inc["session_id"]: inc for inc in incidents_res["items"]
        }

        if mode == "LIVE_MODULE3_API":
            try:
                raw_events = self._api_request(f"/api/v1/events?limit={limit}")
                enriched = [
                    self._enrich_event_row(ev, incidents_by_session, mode)
                    for ev in raw_events
                ]
                filtered = self._filter_event_list(enriched, severity, incident_status, search)
                return {"items": filtered[:limit], "data_source": mode, "is_mock_data": False}
            except Exception:
                if not MODULE3_AVAILABLE:
                    events = self._filter_event_list(list(self._fallback_events), severity, incident_status, search)
                    return {"items": events[:limit], "data_source": "SYNTHETIC_FALLBACK", "is_mock_data": True}
                mode = "DIRECT_PIPELINE"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()

        enriched = [self._enrich_event_row(r, incidents_by_session, mode) for r in rows]
        filtered = self._filter_event_list(enriched, severity, incident_status, search)
        return {"items": filtered, "data_source": mode, "is_mock_data": False}

    @staticmethod
    def _filter_event_list(
        events: list[dict[str, Any]],
        severity: Optional[str],
        incident_status: Optional[str],
        search: Optional[str],
    ) -> list[dict[str, Any]]:
        out = events
        if severity and severity.lower() != "all":
            sev_l = severity.strip().lower()
            out = [e for e in out if str(e.get("severity", "")).lower() == sev_l]
        if incident_status and incident_status.lower() != "all":
            st_l = incident_status.strip().lower()
            out = [e for e in out if str(e.get("incident_status", "")).lower() == st_l]
        if search:
            q = search.strip().lower()
            out = [
                e for e in out
                if q in str(e.get("event_id", "")).lower()
                or q in str(e.get("session_id", "")).lower()
                or q in str(e.get("user_alias", "")).lower()
                or q in str(e.get("detection_reason", "")).lower()
                or q in str(e.get("source_ip", "")).lower()
                or q in str(e.get("scenario", "")).lower()
            ]
        return out

    def get_incidents(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            items = self._filter_incident_list(list(self._fallback_incidents), severity, status, search)
            return {"items": items, "data_source": mode, "is_mock_data": True}

        self.ensure_baseline_ingested()

        if mode == "LIVE_MODULE3_API":
            try:
                raw = self._api_request("/api/v1/incidents")
                for inc in raw:
                    inc["is_mock_data"] = False
                    inc["data_source"] = mode
                items = self._filter_incident_list(raw, severity, status, search)
                return {"items": items, "data_source": mode, "is_mock_data": False}
            except Exception:
                if not MODULE3_AVAILABLE:
                    items = self._filter_incident_list(list(self._fallback_incidents), severity, status, search)
                    return {"items": items, "data_source": "SYNTHETIC_FALLBACK", "is_mock_data": True}
                mode = "DIRECT_PIPELINE"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM incidents ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()

        items = []
        for r in rows:
            d = dict(r)
            d["signals"] = json.loads(d["signals_json"]) if d.get("signals_json") else {}
            d["formula_breakdown"] = (
                json.loads(d["formula_breakdown_json"]) if d.get("formula_breakdown_json") else {}
            )
            d["recommendations"] = (
                json.loads(d["recommendations_json"]) if d.get("recommendations_json") else []
            )
            d["is_mock_data"] = False
            d["data_source"] = mode
            items.append(d)

        filtered = self._filter_incident_list(items, severity, status, search)
        return {"items": filtered, "data_source": mode, "is_mock_data": False}

    @staticmethod
    def _filter_incident_list(
        incidents: list[dict[str, Any]],
        severity: Optional[str],
        status: Optional[str],
        search: Optional[str],
    ) -> list[dict[str, Any]]:
        out = incidents
        if severity and severity.lower() != "all":
            sev_l = severity.strip().lower()
            out = [i for i in out if str(i.get("severity", "")).lower() == sev_l]
        if status and status.lower() != "all":
            st_l = status.strip().lower()
            out = [i for i in out if str(i.get("status", "")).lower() == st_l]
        if search:
            q = search.strip().lower()
            out = [
                i for i in out
                if q in str(i.get("incident_id", "")).lower()
                or q in str(i.get("session_id", "")).lower()
                or q in str(i.get("title", "")).lower()
                or q in str(i.get("user_alias", "")).lower()
                or q in str(i.get("scenario", "")).lower()
            ]
        return out

    def get_incident_details(self, incident_id: str) -> Optional[dict[str, Any]]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            inc = next((i for i in self._fallback_incidents if i["incident_id"] == incident_id), None)
            if not inc:
                return None
            out = dict(inc)
            out["timeline"] = [
                {
                    "event_id": "DEMO-EVT",
                    "timestamp": out["created_at"],
                    "stage": "Simulated AiTM Detection",
                    "details": out["title"],
                }
            ]
            out["session_current_status"] = "active"
            return out

        if mode == "LIVE_MODULE3_API":
            try:
                inc = self._api_request(f"/api/v1/incidents/{incident_id}")
                inc["is_mock_data"] = False
                inc["data_source"] = mode
                return inc
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return None
            except Exception:
                if not MODULE3_AVAILABLE:
                    return None
                mode = "DIRECT_PIPELINE"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return None

        incident = dict(row)
        incident["signals"] = json.loads(incident["signals_json"]) if incident.get("signals_json") else {}
        incident["formula_breakdown"] = (
            json.loads(incident["formula_breakdown_json"]) if incident.get("formula_breakdown_json") else {}
        )
        incident["recommendations"] = (
            json.loads(incident["recommendations_json"]) if incident.get("recommendations_json") else []
        )

        c.execute("SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC", (incident["session_id"],))
        timeline = []
        for er in c.fetchall():
            ed = dict(er)
            timeline.append({
                "event_id": ed["event_id"],
                "timestamp": ed["timestamp"],
                "stage": "Initial Phishing Inbound / Redirect" if ed["redirect_count"] > 1 else "Authentication Sign-in",
                "details": f"Observed {ed['redirect_count']} hops from {ed['source_ip']} (TLS Anomaly: {bool(ed['tls_anomaly'])})",
                "redirect_chain": json.loads(ed["redirect_chain"]) if ed.get("redirect_chain") else [],
            })

        if incident["signals"].get("replay_indicator"):
            timeline.append({
                "timestamp": incident["updated_at"],
                "stage": "Simulated Token Replay Indicator",
                "details": "Synthetic session token flagged for divergent client/IP replay context.",
            })

        c.execute("SELECT status FROM sessions WHERE session_id = ?", (incident["session_id"],))
        sess_row = c.fetchone()
        conn.close()

        incident["timeline"] = timeline
        incident["session_current_status"] = sess_row["status"] if sess_row else "unknown"
        incident["is_mock_data"] = False
        incident["data_source"] = mode
        return incident

    def update_incident_status(self, incident_id: str, new_status: str) -> Optional[dict[str, Any]]:
        mode = self.get_active_mode()
        now_iso = datetime.now(timezone.utc).isoformat()

        if mode == "SYNTHETIC_FALLBACK":
            inc = next((i for i in self._fallback_incidents if i["incident_id"] == incident_id), None)
            if not inc:
                return None
            inc["status"] = new_status
            inc["updated_at"] = now_iso
            return {
                "incident_id": incident_id,
                "new_status": new_status,
                "updated_at": now_iso,
                "data_source": mode,
                "is_mock_data": True,
            }

        if mode == "LIVE_MODULE3_API":
            try:
                existing = self.get_incident_details(incident_id)
                if not existing:
                    return None
                res = self._api_request(
                    f"/api/v1/incidents/{incident_id}/status",
                    method="PATCH",
                    payload={"status": new_status},
                )
                res["data_source"] = mode
                res["is_mock_data"] = False
                return res
            except Exception:
                if not MODULE3_AVAILABLE:
                    return None
                mode = "DIRECT_PIPELINE"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
            (new_status, now_iso, incident_id),
        )
        updated_rows = c.rowcount
        conn.commit()
        conn.close()

        if updated_rows == 0:
            return None

        return {
            "incident_id": incident_id,
            "new_status": new_status,
            "updated_at": now_iso,
            "data_source": mode,
            "is_mock_data": False,
        }

    def get_sessions(self) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            return {"items": list(self._fallback_sessions), "data_source": mode, "is_mock_data": True}

        self.ensure_baseline_ingested()
        if mode == "LIVE_MODULE3_API":
            try:
                sessions = self._api_request("/api/v1/sessions")
                for s in sessions:
                    s["is_mock_data"] = False
                    s["data_source"] = mode
                return {"items": sessions, "data_source": mode, "is_mock_data": False}
            except Exception:
                if not MODULE3_AVAILABLE:
                    return {"items": list(self._fallback_sessions), "data_source": "SYNTHETIC_FALLBACK", "is_mock_data": True}
                mode = "DIRECT_PIPELINE"

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM sessions ORDER BY created_at DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        for r in rows:
            r["is_mock_data"] = False
            r["data_source"] = mode
        return {"items": rows, "data_source": mode, "is_mock_data": False}

    def revoke_session(self, session_id: str, performed_by: str = "SOC-Analyst") -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            for s in self._fallback_sessions:
                if s["session_id"] == session_id:
                    s["status"] = "revoked"
                    s["revoked_at"] = datetime.now(timezone.utc).isoformat()
            return {
                "session_id": session_id,
                "status": "revoked",
                "message": f"[DEMO FALLBACK] Session {session_id} marked revoked in memory.",
                "is_mock_data": True,
                "data_source": mode,
            }

        if mode == "LIVE_MODULE3_API":
            try:
                res = self._api_request(
                    f"/api/v1/sessions/{session_id}/revoke",
                    method="POST",
                    payload={"performed_by": performed_by},
                )
                res["is_mock_data"] = False
                res["data_source"] = mode
                return res
            except Exception:
                if not MODULE3_AVAILABLE:
                    raise

        res = revoke_session_db(session_id, performed_by=performed_by)
        res["is_mock_data"] = False
        res["data_source"] = mode
        return res

    def test_session_access(self, session_id: str) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "SYNTHETIC_FALLBACK":
            sess = next((s for s in self._fallback_sessions if s["session_id"] == session_id), None)
            if not sess:
                return {"session_id": session_id, "access_granted": False, "status_code": 404, "is_mock_data": True}
            revoked = sess["status"] == "revoked"
            return {
                "session_id": session_id,
                "access_granted": not revoked,
                "status_code": 401 if revoked else 200,
                "containment_proven": revoked,
                "detail": "Demo session revoked" if revoked else "Demo session active",
                "is_mock_data": True,
            }

        if mode == "LIVE_MODULE3_API":
            try:
                return self._api_request(f"/api/v1/sessions/{session_id}/test_access", method="POST")
            except Exception:
                if not MODULE3_AVAILABLE:
                    raise

        return verify_session_access(session_id)

    def get_lab_scenarios(self) -> list[dict[str, Any]]:
        mode = self.get_active_mode()
        if mode == "LIVE_MODULE3_API":
            try:
                return self._api_request("/api/v1/lab/scenarios")
            except Exception:
                pass
        if MODULE3_AVAILABLE and not self.force_fallback:
            return list_scenarios()
        return []

    def run_lab_scenario(self, scenario_id: str) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "LIVE_MODULE3_API":
            try:
                res = self._api_request(f"/api/v1/lab/scenarios/{scenario_id}/run", method="POST")
                res["data_source"] = mode
                res["is_mock_data"] = False
                return res
            except Exception:
                if not MODULE3_AVAILABLE:
                    raise
                mode = "DIRECT_PIPELINE"

        if not (MODULE2_AVAILABLE and MODULE3_AVAILABLE) or self.force_fallback:
            raise RuntimeError("Lab scenarios require Module 2 and Module 3.")

        res = run_lab_scenario(
            scenario_id=scenario_id,
            detector=self._detector,
            hardening_engine=self._hardening_engine,
            session_tracker=self._session_tracker,
            tls_analyzer=self._tls_analyzer,
        )
        res["data_source"] = mode
        res["is_mock_data"] = False
        return res

    def reset_lab_data(self) -> dict[str, Any]:
        if self.force_fallback or not MODULE3_AVAILABLE:
            self._fallback_events = [dict(e) for e in FALLBACK_EVENTS]
            self._fallback_incidents = [dict(i) for i in FALLBACK_INCIDENTS]
            self._fallback_sessions = [dict(s) for s in FALLBACK_SESSIONS]
            return {"status": "success", "message": "Fallback demo data reset.", "is_mock_data": True}

        res = reset_test_data()
        if self._session_tracker is not None:
            self._session_tracker.reset()
        return res

    # ------------------------------------------------------------------
    # Module 3 Hardening, FIDO2 & Auth Matrix Integration
    # ------------------------------------------------------------------

    def get_hardening_overview(self) -> dict[str, Any]:
        mode = self.get_active_mode()
        if mode == "LIVE_MODULE3_API":
            try:
                auth_methods = self._api_request("/api/defense/auth-methods")
                origin_binding = self._api_request("/api/defense/origin-binding")
                token_binding = self._api_request("/api/defense/token-binding")
                checklist = self._api_request("/api/v1/hardening/checklist")
                return {
                    "auth_methods": auth_methods,
                    "origin_binding": origin_binding,
                    "token_binding": token_binding,
                    "checklist": checklist,
                    "data_source": mode,
                    "is_mock_data": False,
                }
            except Exception:
                if not MODULE3_AVAILABLE:
                    pass

        if MODULE3_AVAILABLE and not self.force_fallback:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM hardening_checklist_items ORDER BY item_id ASC")
            checklist_rows = [dict(r) for r in c.fetchall()]
            conn.close()
            return {
                "auth_methods": [p.to_dict() for p in self._auth_kb.get_all_profiles()],
                "origin_binding": self._auth_kb.explain_origin_binding(),
                "token_binding": self._auth_kb.explain_token_binding(),
                "checklist": checklist_rows,
                "data_source": "DIRECT_PIPELINE",
                "is_mock_data": False,
            }

        return {
            "auth_methods": [],
            "origin_binding": {},
            "token_binding": {},
            "checklist": [],
            "data_source": "SYNTHETIC_FALLBACK",
            "is_mock_data": True,
        }

    def update_checklist_item(self, item_id: str, status: str, notes: Optional[str] = None) -> Optional[dict[str, Any]]:
        if self.force_fallback or not MODULE3_AVAILABLE:
            return None

        mode = self.get_active_mode()
        if mode == "LIVE_MODULE3_API":
            try:
                payload: dict[str, Any] = {"status": status}
                if notes is not None:
                    payload["notes"] = notes
                return self._api_request(f"/api/v1/hardening/checklist/{item_id}", method="PATCH", payload=payload)
            except Exception:
                pass

        conn = get_db_connection()
        c = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()
        if notes is not None:
            c.execute(
                "UPDATE hardening_checklist_items SET status = ?, notes = ?, last_reviewed = ? WHERE item_id = ?",
                (status, notes, now_iso, item_id),
            )
        else:
            c.execute(
                "UPDATE hardening_checklist_items SET status = ?, last_reviewed = ? WHERE item_id = ?",
                (status, now_iso, item_id),
            )
        if c.rowcount == 0:
            conn.close()
            return None
        conn.commit()
        c.execute("SELECT * FROM hardening_checklist_items WHERE item_id = ?", (item_id,))
        row = dict(c.fetchone())
        conn.close()
        return row
