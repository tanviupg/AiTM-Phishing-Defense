"""
Database and Persistence Layer for AiTM Sentinel (Module 3 & System-wide).
Provides a lightweight, zero-dependency SQLite repository for:
- Normalized Security Events (Screen 03: Event Explorer)
- Security Incidents & Timeline Triage (Screen 04: Incident Investigation)
- Synthetic Sessions & Defensive Containment (Screen 05: Session Management)
- Configurable Detection Rules (Screen 06: Detection Rules)
- Hardening Checklist Audit (Screen 07: Security Hardening)
- Lab Scenario Execution Logs (Screen 02: Detection Lab)
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "aitm_sentinel.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with dict-like row access."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            user_alias TEXT NOT NULL,
            scenario TEXT NOT NULL,
            auth_result TEXT NOT NULL,
            redirect_count INTEGER NOT NULL,
            redirect_chain TEXT NOT NULL,
            tls_anomaly INTEGER NOT NULL,
            replay_indicator INTEGER NOT NULL,
            source_ip TEXT,
            device_id TEXT,
            severity TEXT DEFAULT 'Low',
            raw_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # 2. Incidents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            user_alias TEXT NOT NULL,
            scenario TEXT NOT NULL,
            signals_json TEXT NOT NULL,
            formula_breakdown_json TEXT NOT NULL,
            recommendations_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # 3. Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_alias TEXT NOT NULL,
            client_context TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            replay_indicator INTEGER NOT NULL DEFAULT 0,
            scenario TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        )
    """)

    # 4. Containment Audit Log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS containment_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            session_id TEXT NOT NULL,
            action TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    # 5. Detection Rules table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            weight INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            condition_desc TEXT NOT NULL,
            last_tested TEXT
        )
    """)

    # 6. Hardening Checklist items table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardening_checklist_items (
            item_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Not assessed',
            description TEXT NOT NULL,
            mitigation_detail TEXT NOT NULL,
            notes TEXT DEFAULT '',
            last_reviewed TEXT
        )
    """)

    conn.commit()

    # Pre-populate detection rules if table is empty
    cursor.execute("SELECT COUNT(*) as cnt FROM detection_rules")
    if cursor.fetchone()["cnt"] == 0:
        rules = [
            ("DET-001", "Unapproved Domain Anomaly", "Detect unexpected authentication destinations and spoofed IdP domains", "High", 30, 1, "observed_domain not in approved_idp_list or CERT_HOSTNAME_MISMATCH"),
            ("DET-002", "Redirect Chain Anomaly", "Identify suspicious redirect sequences, cyclic hops, or proxy transitions", "Medium", 15, 1, "redirect_count > 3 or SUSPICIOUS_REDIRECT_CYCLE"),
            ("DET-003", "Session Replay Indicator", "Detect synthetic session reuse across divergent client contexts or rapid IPs", "High", 25, 1, "replay_indicator == True or TOKEN_BINDING_FAILURE or CONCURRENT_SESSION_BIFURCATION"),
            ("DET-004", "Post-Revocation Access", "Flag and block any attempted access with a revoked synthetic session token", "Critical", 35, 1, "session.status == 'revoked'"),
            ("DET-005", "Context Inconsistency Anomaly", "Identify rapid IP transitions (<60s) or device fingerprint divergence", "Low", 10, 1, "RAPID_SOURCE_IP_CHANGE or CLIENT_PLATFORM_DIVERGENCE"),
        ]
        cursor.executemany("""
            INSERT INTO detection_rules (rule_id, name, description, severity, weight, enabled, condition_desc, last_tested)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, rules)
        conn.commit()

    # Pre-populate default hardening checklist items if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM hardening_checklist_items")
    if cursor.fetchone()["cnt"] == 0:
        checklist_seed = [
            ("CHK-FIDO2-01", "FIDO2 / WebAuthn Origin-Bound Authentication", "Phishing-Resistant MFA", "CRITICAL", "Verified", "Enforce FIDO2 security keys or passkeys bound cryptographically to relying party ID (rpId).", "Eliminates credential and session theft from AiTM reverse proxies via cryptographic channel binding."),
            ("CHK-FIDO2-02", "Eliminate SMS and Voice OTP Fallbacks", "Credential Security", "HIGH", "In progress", "Disable legacy telephonic OTP channels for sensitive corporate applications.", "SMS OTP is completely relayed by live AiTM proxies (e.g., Evilginx2)."),
            ("CHK-TOK-01", "Cryptographic Token Protection (DPoP / mTLS)", "Token Protection", "CRITICAL", "Verified", "Bind OAuth 2.0 access/refresh tokens to client private key pairs (RFC 9449).", "Even if proxy intercepts session token, replay fails without client private key."),
            ("CHK-CA-01", "Continuous Access Evaluation (CAE)", "Session Security", "HIGH", "In progress", "Configure near real-time session revocation on IP or device state change.", "Terminates hijacked sessions within seconds of anomaly detection."),
            ("CHK-DEV-01", "Managed Device Compliance Enforcement", "Device Trust", "HIGH", "In progress", "Require Intune/JAMF device compliance and device certificates for IdP access.", "Blocks attacker machines lacking the corporate root CA trust chain."),
            ("CHK-MON-01", "SOC Multi-Signal Correlation & Anomaly Monitoring", "Monitoring & Logging", "HIGH", "Verified", "Correlate redirect hops, TLS certificate anomalies, and temporal session IP shifts.", "Enables early detection and automatic containment before lateral movement."),
            ("CHK-IR-01", "Automated Session Revocation Incident Response Playbook", "Incident Response", "CRITICAL", "Verified", "Establish automated one-click or automated session token revocation endpoints.", "Stops attacker replay immediately upon high-risk alert trigger."),
            ("CHK-TRN-01", "AiTM Phishing Awareness & Domain Verification Training", "User Training", "MEDIUM", "Verified", "Train employees on domain inspection and passkey prompts vs. fake login pages.", "Reduces initial click-through rate to adversary-controlled reverse proxy links.")
        ]
        cursor.executemany("""
            INSERT INTO hardening_checklist_items (item_id, title, category, priority, status, description, mitigation_detail, last_reviewed)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, checklist_seed)
        conn.commit()

    conn.close()


def record_event(event_dict: dict[str, Any], severity: str = "Low") -> None:
    """Inserts a normalized security event into the persistent store."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    chain_json = json.dumps(event_dict.get("redirect_chain", []))
    raw_json = json.dumps(event_dict)

    cursor.execute("""
        INSERT OR REPLACE INTO events (
            event_id, timestamp, session_id, user_alias, scenario, auth_result,
            redirect_count, redirect_chain, tls_anomaly, replay_indicator,
            source_ip, device_id, severity, raw_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_dict.get("event_id", f"EVT-{event_dict.get('session_id', 'UNKNOWN')}"),
        event_dict.get("timestamp", now_iso),
        event_dict.get("session_id", "UNKNOWN"),
        event_dict.get("user_alias", event_dict.get("device_id", "lab-user")),
        event_dict.get("scenario", "default"),
        event_dict.get("auth_result", "success"),
        int(event_dict.get("redirect_count", 0)),
        chain_json,
        1 if event_dict.get("tls_anomaly") else 0,
        1 if event_dict.get("replay_indicator") else 0,
        event_dict.get("source_ip", "127.0.0.1"),
        event_dict.get("device_id", "DEV-01"),
        severity,
        raw_json,
        now_iso,
    ))
    conn.commit()
    conn.close()


def record_incident(incident_dict: dict[str, Any]) -> None:
    """Inserts or updates an incident record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT OR REPLACE INTO incidents (
            incident_id, session_id, title, severity, risk_score, risk_level,
            status, user_alias, scenario, signals_json, formula_breakdown_json,
            recommendations_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident_dict["incident_id"],
        incident_dict["session_id"],
        incident_dict["title"],
        incident_dict["severity"],
        incident_dict["risk_score"],
        incident_dict["risk_level"],
        incident_dict.get("status", "Open"),
        incident_dict.get("user_alias", "LAB-USER"),
        incident_dict.get("scenario", "default"),
        json.dumps(incident_dict.get("signals", {})),
        json.dumps(incident_dict.get("formula_breakdown", {})),
        json.dumps(incident_dict.get("recommendations", [])),
        incident_dict.get("created_at", now_iso),
        now_iso,
    ))
    conn.commit()
    conn.close()


def record_session(
    session_id: str,
    user_alias: str,
    client_context: str,
    source_ip: str,
    scenario: str,
    replay_indicator: bool = False,
) -> None:
    """Inserts or updates a synthetic session record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT OR REPLACE INTO sessions (
            session_id, user_alias, client_context, source_ip, status,
            replay_indicator, scenario, created_at
        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
    """, (
        session_id,
        user_alias,
        client_context,
        source_ip,
        1 if replay_indicator else 0,
        scenario,
        now_iso,
    ))
    conn.commit()
    conn.close()


def revoke_session_db(session_id: str, performed_by: str = "SOC-Analyst") -> dict[str, Any]:
    """Revokes a session and logs the defensive containment action."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        UPDATE sessions
        SET status = 'revoked', revoked_at = ?
        WHERE session_id = ?
    """, (now_iso, session_id))

    # Also update any open incidents for this session to Contained
    cursor.execute("""
        UPDATE incidents
        SET status = 'Contained', updated_at = ?
        WHERE session_id = ? AND status != 'Resolved'
    """, (now_iso, session_id))

    cursor.execute("""
        INSERT INTO containment_audit_log (timestamp, session_id, action, performed_by, status, details)
        VALUES (?, ?, 'REVOKE_SESSION', ?, 'SUCCESS', 'Synthetic session revoked; subsequent requests rejected')
    """, (now_iso, session_id, performed_by))

    conn.commit()
    conn.close()

    return {
        "session_id": session_id,
        "status": "revoked",
        "revoked_at": now_iso,
        "containment_verified": True,
        "message": f"Session {session_id} successfully revoked. Token replay is now neutralized."
    }


def verify_session_access(session_id: str) -> dict[str, Any]:
    """
    Simulates a client test request using session_id.
    If session is active -> 200 OK.
    If session is revoked -> 401 Unauthorized (Defensive containment proven).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {
            "session_id": session_id,
            "access_granted": False,
            "status_code": 404,
            "detail": "Session not found in active session store."
        }

    if row["status"] == "revoked":
        return {
            "session_id": session_id,
            "access_granted": False,
            "status_code": 401,
            "detail": "ACCESS DENIED: Session has been revoked by SOC containment action.",
            "containment_proven": True
        }

    return {
        "session_id": session_id,
        "access_granted": True,
        "status_code": 200,
        "detail": "ACCESS GRANTED: Session is active.",
        "containment_proven": False
    }


def reset_test_data() -> dict[str, Any]:
    """Resets database to clean initial baseline for isolated lab testing."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM sessions")
    cursor.execute("DELETE FROM containment_audit_log")
    conn.commit()
    conn.close()
    init_db()
    return {"status": "success", "message": "Isolated lab test data reset to baseline."}


# Initialize tables on import
init_db()
