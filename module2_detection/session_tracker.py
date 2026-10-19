"""
Session Tracker for Temporal Authentication Event Correlation (Module 2, Stage 1).

Defensive, lab-only, in-memory correlation of synthetic authentication events across time.
Tracks session context transitions (IP address and device identifiers) over configurable time windows.

Safety & Security Guarantees:
1. Never inspects, collects, or stores real passwords, cookies, or session tokens.
2. Operates strictly on high-level synthetic telemetry (session_id, timestamp, source_ip, device_id).
3. Agnostic to ground-truth labels: Does NOT read or use 'scenario', 'ground_truth', or 'replay_indicator'.
4. Does NOT treat an IP change or device mismatch alone as conclusive proof of token theft;
   instead emits explainable indicators for investigative risk scoring and human review.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class SessionRecord:
    """Historical snapshot of an event within a session."""
    timestamp: datetime
    source_ip: Optional[str]
    device_id: Optional[str]
    asn_type: Optional[str] = None
    client_platform: Optional[str] = None
    client_tls_fingerprint: Optional[str] = None
    token_binding_status: Optional[str] = None


@dataclass
class CorrelationResult:
    """Structured, explainable output from temporal session correlation."""
    session_id: str
    is_correlated: bool
    event_count: int
    delta_seconds: Optional[float]
    indicators: list[str]
    explanation: str
    context_details: dict[str, Any] = field(default_factory=dict)


def parse_iso_timestamp(ts: Any) -> datetime:
    """
    Parses ISO-8601 timestamp strings, numeric epochs, or datetime objects into UTC datetime.
    Policy: Naive timestamps without timezone information are explicitly attached with UTC
    (replace tzinfo=timezone.utc); host machine local timezone conversion is never used.
    Raises ValueError if timestamp cannot be parsed.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    if isinstance(ts, str):
        # Support trailing 'Z' shorthand for UTC
        cleaned = ts.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(cleaned)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Invalid ISO-8601 timestamp string '{ts}': {err}")

        # Explicit UTC policy for naive datetimes: never use local timezone
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    raise ValueError(f"Unsupported timestamp type: {type(ts).__name__}")


class SessionTracker:
    """
    In-memory correlation tracker for synthetic authentication events.

    Tracks sequential authentication and access events sharing the same session_id.
    Emits explainable indicators for device context changes and rapid IP shifts.

    Limitations:
    - Purely in-memory: State is not persisted to disk and resets on process restart.
    - Designed for single-node lab evaluation; not distributed or synchronized across workers.
    - Temporal context indicators reflect heuristic patterns, not conclusive proof of token theft.
    """

    def __init__(
        self,
        correlation_window_seconds: float = 3600.0,
        rapid_source_window_seconds: float = 60.0,
    ):
        """
        Args:
            correlation_window_seconds: Maximum time difference between events to consider them
                                       part of the same active session window (default: 3600s / 1 hour).
            rapid_source_window_seconds: Threshold for flagging rapid IP shifts (default: 60s).
        """
        if correlation_window_seconds <= 0:
            raise ValueError("correlation_window_seconds must be positive")
        if rapid_source_window_seconds <= 0:
            raise ValueError("rapid_source_window_seconds must be positive")

        self.correlation_window_seconds = float(correlation_window_seconds)
        self.rapid_source_window_seconds = float(rapid_source_window_seconds)

        # In-memory session store: session_id -> list of SessionRecord (ordered chronologically)
        self._sessions: dict[str, list[SessionRecord]] = {}

    def reset(self) -> None:
        """Clears all in-memory session tracking state."""
        self._sessions.clear()

    def prune_expired_sessions(self, reference_time: Optional[datetime] = None) -> int:
        """
        Removes sessions whose most recent event is older than correlation_window_seconds.
        Returns the count of pruned sessions.
        """
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        expired_ids = []
        for sid, records in self._sessions.items():
            if not records:
                expired_ids.append(sid)
                continue
            last_event_time = records[-1].timestamp
            if (reference_time - last_event_time).total_seconds() > self.correlation_window_seconds:
                expired_ids.append(sid)

        for sid in expired_ids:
            del self._sessions[sid]

        return len(expired_ids)

    def correlate_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Analyzes a synthetic authentication event against active session history.
        Returns a dictionary representation of CorrelationResult.

        Guaranteed:
        - Never reads or references 'scenario', 'ground_truth', or 'replay_indicator'.
        - Never collects passwords, tokens, or cookies.
        """
        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        session_id = event.get("session_id")
        if not session_id or not isinstance(session_id, str):
            raise ValueError("session_id must be a non-empty string")

        # Extract token_binding_status early so it is never dropped on missing/invalid timestamp
        raw_token_binding = event.get("token_binding_status")
        token_binding_status = (
            raw_token_binding.strip().lower()
            if isinstance(raw_token_binding, str)
            else None
        )
        tb_failed = token_binding_status in ("failed", "key_mismatch")

        # 1. Parse and validate timestamp
        raw_ts = event.get("timestamp")
        if raw_ts is None:
            indicators = ["MISSING_TIMESTAMP"]
            reasons = ["event is missing required 'timestamp' field"]
            if tb_failed:
                indicators.append("TOKEN_BINDING_FAILURE")
                reasons.append(
                    f"cryptographic token proof-of-possession binding validation failed (status: '{raw_token_binding}')"
                )
            context_details: dict[str, Any] = {"session_id": session_id}
            if raw_token_binding is not None:
                context_details["token_binding_status"] = raw_token_binding

            return asdict(
                CorrelationResult(
                    session_id=session_id,
                    is_correlated=False,
                    event_count=0,
                    delta_seconds=None,
                    indicators=indicators,
                    explanation="; ".join(reasons),
                    context_details=context_details,
                )
            )

        try:
            current_time = parse_iso_timestamp(raw_ts)
        except (ValueError, TypeError) as err:
            indicators = ["INVALID_TIMESTAMP"]
            reasons = [f"timestamp could not be parsed: {err}"]
            if tb_failed:
                indicators.append("TOKEN_BINDING_FAILURE")
                reasons.append(
                    f"cryptographic token proof-of-possession binding validation failed (status: '{raw_token_binding}')"
                )
            context_details = {"raw_timestamp": raw_ts}
            if raw_token_binding is not None:
                context_details["token_binding_status"] = raw_token_binding

            return asdict(
                CorrelationResult(
                    session_id=session_id,
                    is_correlated=False,
                    event_count=0,
                    delta_seconds=None,
                    indicators=indicators,
                    explanation="; ".join(reasons),
                    context_details=context_details,
                )
            )

        # 2. Extract context attributes (source_ip, device_id, and optional replay telemetry)
        source_ip = event.get("source_ip")
        device_id = event.get("device_id")

        asn_type = event.get("asn_type")
        if isinstance(asn_type, str):
            asn_type = asn_type.strip().lower()
        else:
            asn_type = None

        client_platform = event.get("client_platform")
        if isinstance(client_platform, str):
            client_platform = client_platform.strip().lower()
        else:
            client_platform = None

        client_tls_fingerprint = event.get("client_tls_fingerprint")
        if isinstance(client_tls_fingerprint, str):
            client_tls_fingerprint = client_tls_fingerprint.strip()
            if not client_tls_fingerprint:
                client_tls_fingerprint = None
        else:
            client_tls_fingerprint = None

        indicators = []
        reasons = []

        # Check Token Binding Failure (can occur on initial or subsequent requests)
        if tb_failed:
            indicators.append("TOKEN_BINDING_FAILURE")
            reasons.append(
                f"cryptographic token proof-of-possession binding validation failed (status: '{raw_token_binding}')"
            )

        missing_fields = []
        if source_ip is None:
            missing_fields.append("source_ip")
        if device_id is None:
            missing_fields.append("device_id")

        if missing_fields:
            indicators.append("MISSING_TELEMETRY")
            reasons.append(f"event lacks context telemetry: {', '.join(missing_fields)}")

        records = self._sessions.setdefault(session_id, [])

        # 3. First event for this session
        if not records:
            new_record = SessionRecord(
                timestamp=current_time,
                source_ip=source_ip,
                device_id=device_id,
                asn_type=asn_type,
                client_platform=client_platform,
                client_tls_fingerprint=client_tls_fingerprint,
                token_binding_status=token_binding_status,
            )
            records.append(new_record)
            indicators.append("INITIAL_SESSION_EVENT")
            explanation = "initial observed event for session; baseline context established"
            if reasons:
                explanation = f"{explanation}; {'; '.join(reasons)}"

            return asdict(
                CorrelationResult(
                    session_id=session_id,
                    is_correlated=False,
                    event_count=1,
                    delta_seconds=0.0,
                    indicators=indicators,
                    explanation=explanation,
                    context_details={
                        "source_ip": source_ip,
                        "device_id": device_id,
                        "timestamp": current_time.isoformat(),
                        "asn_type": asn_type,
                        "client_platform": client_platform,
                        "client_tls_fingerprint": client_tls_fingerprint,
                        "token_binding_status": raw_token_binding,
                    },
                )
            )

        # 4. Handle Duplicate Events
        is_duplicate = any(
            r.timestamp == current_time
            and r.source_ip == source_ip
            and r.device_id == device_id
            for r in records
        )
        if is_duplicate:
            indicators.append("DUPLICATE_EVENT")
            reasons.append("identical event timestamp and context received more than once")
            context_details = {
                "duplicate_of_timestamp": current_time.isoformat(),
                "total_records": len(records),
            }
            if raw_token_binding is not None:
                context_details["token_binding_status"] = raw_token_binding
            return asdict(
                CorrelationResult(
                    session_id=session_id,
                    is_correlated=True,
                    event_count=len(records),
                    delta_seconds=0.0,
                    indicators=indicators,
                    explanation="; ".join(reasons),
                    context_details=context_details,
                )
            )

        # 5. Determine Chronological Predecessor and Out-of-Order Status
        predecessors = [r for r in records if r.timestamp <= current_time]
        successors = [r for r in records if r.timestamp > current_time]

        is_out_of_order = len(successors) > 0
        if is_out_of_order:
            latest_recorded_event = successors[-1]
            indicators.append("OUT_OF_ORDER_EVENT")
            reasons.append(
                f"event timestamp ({current_time.isoformat()}) is earlier than recorded event ({latest_recorded_event.timestamp.isoformat()})"
            )

        # In-order arrival: check session window expiry against latest recorded event
        if not is_out_of_order:
            predecessor_record = records[-1]
            delta_seconds = (current_time - predecessor_record.timestamp).total_seconds()
            if delta_seconds > self.correlation_window_seconds:
                indicators.append("SESSION_WINDOW_EXPIRED")
                reasons.append(
                    f"time delta ({delta_seconds:.1f}s) exceeds correlation window ({self.correlation_window_seconds:.1f}s); context tracking reset"
                )
                # Reset session state with current event as new anchor
                records.clear()
                records.append(
                    SessionRecord(
                        timestamp=current_time,
                        source_ip=source_ip,
                        device_id=device_id,
                        asn_type=asn_type,
                        client_platform=client_platform,
                        client_tls_fingerprint=client_tls_fingerprint,
                        token_binding_status=token_binding_status,
                    )
                )
                return asdict(
                    CorrelationResult(
                        session_id=session_id,
                        is_correlated=False,
                        event_count=1,
                        delta_seconds=delta_seconds,
                        indicators=indicators,
                        explanation="; ".join(reasons),
                        context_details={
                            "delta_seconds": delta_seconds,
                            "source_ip": source_ip,
                            "device_id": device_id,
                            "asn_type": asn_type,
                            "client_platform": client_platform,
                            "client_tls_fingerprint": client_tls_fingerprint,
                            "token_binding_status": raw_token_binding,
                        },
                    )
                )
        else:
            # Out-of-order arrival: determine true chronological predecessor if available
            if predecessors:
                predecessor_record = predecessors[-1]
                delta_seconds = (current_time - predecessor_record.timestamp).total_seconds()
            else:
                # Event is earlier than all previously observed records in this session
                predecessor_record = None
                delta_seconds = None

        # 6. Evaluate Context Transitions Against Prior Chronological Event (if available)
        prev_device = predecessor_record.device_id if predecessor_record else None
        prev_ip = predecessor_record.source_ip if predecessor_record else None
        prev_asn = predecessor_record.asn_type if predecessor_record else None
        prev_platform = predecessor_record.client_platform if predecessor_record else None
        prev_fingerprint = predecessor_record.client_tls_fingerprint if predecessor_record else None

        device_changed = bool(
            prev_device is not None
            and device_id is not None
            and prev_device != device_id
        )
        ip_changed = bool(
            prev_ip is not None
            and source_ip is not None
            and prev_ip != source_ip
        )

        if device_changed:
            indicators.append("DEVICE_CONTEXT_CHANGED")
            reasons.append(
                f"device identifier changed from '{prev_device}' to '{device_id}' within active session"
            )

        if ip_changed and delta_seconds is not None:
            if delta_seconds < self.rapid_source_window_seconds:
                indicators.append("RAPID_SOURCE_IP_CHANGE")
                reasons.append(
                    f"source IP changed from '{prev_ip}' to '{source_ip}' within {delta_seconds:.1f}s (< {self.rapid_source_window_seconds:.1f}s threshold)"
                )
            else:
                indicators.append("BENIGN_IP_ROAMING_PLAUSIBLE")
                reasons.append(
                    f"source IP changed from '{prev_ip}' to '{source_ip}' after {delta_seconds:.1f}s (consistent with mobile/network roaming)"
                )

        if device_changed and ("RAPID_SOURCE_IP_CHANGE" in indicators):
            indicators.append("SUSPICIOUS_CONTEXT_MISMATCH")
            reasons.append(
                "simultaneous device mismatch and rapid IP transition detected on active session; warrants investigation for session hijacking"
            )

        # 7. Evaluate Replay Metadata Transitions
        # A. Datacenter Source Transition: residential/corporate to datacenter ASN
        if prev_asn in ("residential", "corporate") and asn_type == "datacenter":
            indicators.append("DATACENTER_SOURCE_TRANSITION")
            reasons.append(
                f"network origin transitioned from {prev_asn} to hosting/datacenter ASN ({asn_type}) within active session"
            )

        # B. Client Platform / TLS Fingerprint Divergence
        platform_diverged = bool(
            prev_platform is not None
            and client_platform is not None
            and prev_platform != client_platform
        )
        fingerprint_diverged = bool(
            prev_fingerprint is not None
            and client_tls_fingerprint is not None
            and prev_fingerprint != client_tls_fingerprint
        )
        if platform_diverged or fingerprint_diverged:
            indicators.append("CLIENT_PLATFORM_DIVERGENCE")
            if platform_diverged and fingerprint_diverged:
                reasons.append(
                    f"client platform shifted from '{prev_platform}' to '{client_platform}' and TLS fingerprint shifted"
                )
            elif platform_diverged:
                reasons.append(
                    f"client platform shifted from '{prev_platform}' to '{client_platform}' within active session"
                )
            else:
                reasons.append(
                    f"client TLS fingerprint shifted from '{prev_fingerprint}' to '{client_tls_fingerprint}' within active session"
                )

        # C. Concurrent Session Bifurcation (two distinct IPs alternating across 4 chronological events within 120s)
        new_record = SessionRecord(
            timestamp=current_time,
            source_ip=source_ip,
            device_id=device_id,
            asn_type=asn_type,
            client_platform=client_platform,
            client_tls_fingerprint=client_tls_fingerprint,
            token_binding_status=token_binding_status,
        )
        prospective_records = sorted(records + [new_record], key=lambda r: r.timestamp)
        if len(prospective_records) >= 4:
            r1, r2, r3, r4 = prospective_records[-4:]
            span = (r4.timestamp - r1.timestamp).total_seconds()
            if 0 <= span <= 120.0:
                ip1, ip2, ip3, ip4 = r1.source_ip, r2.source_ip, r3.source_ip, r4.source_ip
                if (
                    ip1 and ip2 and ip3 and ip4
                    and ip1 != ip2
                    and ip1 == ip3
                    and ip2 == ip4
                ):
                    indicators.append("CONCURRENT_SESSION_BIFURCATION")
                    reasons.append(
                        f"concurrent session bifurcation detected: alternating IP addresses ('{ip1}' and '{ip2}') across 4 chronological events within {span:.1f}s"
                    )

        if predecessor_record is not None and not device_changed and not ip_changed and not indicators:
            indicators.append("NORMAL_SESSION_CONTINUATION")
            reasons.append(
                f"consistent session context maintained on device '{device_id}' and IP '{source_ip}'"
            )

        # Append record to history and sort deterministically
        records.append(new_record)
        records.sort(key=lambda r: r.timestamp)

        explanation = (
            "; ".join(reasons)
            if reasons
            else "session event correlated without context anomalies"
        )

        return asdict(
            CorrelationResult(
                session_id=session_id,
                is_correlated=True,
                event_count=len(records),
                delta_seconds=round(delta_seconds, 2) if delta_seconds is not None else None,
                indicators=indicators,
                explanation=explanation,
                context_details={
                    "prior_device": prev_device,
                    "current_device": device_id,
                    "prior_ip": prev_ip,
                    "current_ip": source_ip,
                    "prior_asn": prev_asn,
                    "current_asn": asn_type,
                    "prior_platform": prev_platform,
                    "current_platform": client_platform,
                    "prior_tls_fingerprint": prev_fingerprint,
                    "current_tls_fingerprint": client_tls_fingerprint,
                    "token_binding_status": raw_token_binding,
                    "delta_seconds": round(delta_seconds, 2) if delta_seconds is not None else None,
                },
            )
        )
