"""
TLS and Certificate Anomaly Telemetry Analyzer (Module 2, Stage 2/3).

Defensive, lab-only component for analyzing synthetic TLS/certificate observations
associated with authentication flows.

Core Objectives:
1. Evaluate certificate validity periods, hostname/SAN matching, and issuer context.
2. Produce deterministic, explainable anomaly indicators.
3. Treat missing or partial telemetry as unobserved/inconclusive, NOT as a confirmed anomaly
   and NOT as a verified normal certificate.
4. Separate transport certificate hostname verification from trusted identity-provider domain validation.
5. Document legitimate causes of unusual observations (enterprise TLS interception middleboxes,
   internal test PKI, split-horizon DNS, CDN multi-tenant certs, and clock skew).
6. Support both dictionary and CertificateTelemetry dataclass inputs.
7. Maintain 100% backward compatibility with legacy events.

Safety & Ethics:
- Operates strictly on high-level synthetic telemetry fixtures.
- Never performs live network interception or packet capture.
- Never inspects, collects, or stores passwords, cookies, session tokens, or keys.
- Completely agnostic to ground-truth labels ('scenario', 'replay_indicator', 'ground_truth').
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, Sequence


@dataclass
class CertificateTelemetry:
    """
    Synthetic schema representation of TLS certificate telemetry observed during authentication.
    All fields are optional to support varying sensor visibility and partial observations.
    """
    subject_cn: Optional[str] = None
    subject_alt_names: list[str] = field(default_factory=list)
    issuer_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[str] = None  # ISO-8601 string
    not_after: Optional[str] = None   # ISO-8601 string
    is_self_signed: Optional[bool] = None
    sni_hostname: Optional[str] = None
    observed_hostname: Optional[str] = None  # Explicit endpoint host where cert was observed
    tls_version: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    validation_status: Optional[str] = None  # "valid", "untrusted_root", "expired", "revoked", "unknown"


@dataclass
class TLSAnalysisResult:
    """Structured, explainable output from TLS and certificate telemetry analysis."""
    is_anomaly: bool
    indicators: list[str]
    confidence: str  # "high", "medium", "low", "none"
    explanation: str
    legitimate_causes: list[str]
    details: dict[str, Any] = field(default_factory=dict)


def parse_timestamp(ts: Any) -> Optional[datetime]:
    """
    Safely parse an ISO-8601 string, numeric epoch, or datetime to UTC datetime.
    Policy: Naive timestamps without timezone information are explicitly attached with UTC
    (replace tzinfo=timezone.utc); host machine local timezone conversion is never used.
    Returns None on parsing failure.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        cleaned = ts.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None
    return None


def match_hostname(hostname: str, pattern: str) -> bool:
    """
    Checks if a hostname matches a certificate pattern (supporting standard wildcards like *.example.com).
    RFC 6125 compliant lowercase comparison.
    """
    h = hostname.lower().strip()
    p = pattern.lower().strip()

    if p.startswith("*."):
        # Wildcard matches only a single domain component (e.g. *.example.com matches foo.example.com, not bar.foo.example.com)
        suffix = p[1:]  # .example.com
        if h.endswith(suffix):
            prefix = h[:-len(suffix)]
            if "." not in prefix and len(prefix) > 0:
                return True
        return False
    return h == p


class TLSAnalyzer:
    """
    Evaluator for synthetic TLS/certificate telemetry.

    Identifies discrepancies between requested authentication hostnames and presented certificates,
    temporal validity violations, and untrusted roots while documenting benign enterprise causes.
    """

    KNOWN_BENIGN_CA_SUBSTRINGS = (
        "digicert",
        "let's encrypt",
        "globalsign",
        "microsoft",
        "google trust services",
        "sectigo",
        "amazon",
    )

    def __init__(self, expected_trusted_hosts: Optional[Sequence[str]] = None):
        """
        Args:
            expected_trusted_hosts: Optional allowlist of legitimate IdP/SP hostnames (e.g. ['login.microsoftonline.com']).
                                    Used to verify if the presented domain is an authorized authentication authority.
        """
        self.expected_trusted_hosts: set[str] = set(expected_trusted_hosts) if expected_trusted_hosts else set()

    def analyze_event_tls(
        self,
        event: dict[str, Any],
        reference_time: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """
        Analyzes TLS/certificate telemetry within an authentication event.

        Args:
            event: Event dictionary matching integration schema or extended with 'certificate_telemetry'.
            reference_time: Reference UTC datetime for evaluating certificate validity (defaults to event timestamp or now).

        Returns:
            Dictionary matching TLSAnalysisResult.
        """
        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        if reference_time is None:
            ev_ts = parse_timestamp(event.get("timestamp"))
            reference_time = ev_ts if ev_ts is not None else datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        raw_cert = event.get("certificate_telemetry")

        # Convert CertificateTelemetry instance to dictionary if needed
        if isinstance(raw_cert, CertificateTelemetry):
            raw_cert = asdict(raw_cert)

        # 1. Determine target/observed TLS hostname
        # Precedence:
        # 1. Explicit 'observed_hostname' in certificate_telemetry
        # 2. Explicit 'observed_tls_host' at event root
        # 3. Fallback: chain[0] if redirect_chain exists
        target_host: Optional[str] = None
        if isinstance(raw_cert, dict) and raw_cert.get("observed_hostname"):
            target_host = raw_cert["observed_hostname"]
        elif event.get("observed_tls_host") and isinstance(event.get("observed_tls_host"), str):
            target_host = event["observed_tls_host"]
        else:
            chain = event.get("redirect_chain")
            if isinstance(chain, list) and chain and isinstance(chain[0], str):
                target_host = chain[0]

        # Fallback to legacy boolean if certificate_telemetry is absent
        if raw_cert is None:
            legacy_flag = event.get("tls_anomaly", False)
            if legacy_flag is True:
                return asdict(
                    TLSAnalysisResult(
                        is_anomaly=True,
                        indicators=["LEGACY_TLS_ANOMALY_FLAG"],
                        confidence="medium",
                        explanation="Event source reported a legacy binary TLS anomaly without detailed certificate telemetry.",
                        legitimate_causes=[
                            "Legacy sensor detected transport anomaly, TLS version downgrade, or unparsed certificate error.",
                            "Enterprise TLS proxy or inspection gateway terminated connection."
                        ],
                        details={"legacy_tls_anomaly": True},
                    )
                )
            return asdict(
                TLSAnalysisResult(
                    is_anomaly=False,
                    indicators=["UNOBSERVED_TLS_TELEMETRY"],
                    confidence="none",
                    explanation="No certificate telemetry was provided for this event. Handshake unobserved or uninstrumented.",
                    legitimate_causes=[
                        "Sensor lacks TLS/certificate inspection visibility.",
                        "Authentication endpoint did not record client-side transport metadata."
                    ],
                    details={"missing_telemetry": True, "observed_target_host": target_host},
                )
            )

        if not isinstance(raw_cert, dict):
            return asdict(
                TLSAnalysisResult(
                    is_anomaly=False,
                    indicators=["MALFORMED_CERTIFICATE_TELEMETRY"],
                    confidence="none",
                    explanation="certificate_telemetry must be a dictionary or CertificateTelemetry instance; observation discarded.",
                    legitimate_causes=["Telemetry serialization format error."],
                    details={"raw_type": type(raw_cert).__name__},
                )
            )

        # 2. Extract telemetry fields defensively
        subject_cn = raw_cert.get("subject_cn")
        sans = raw_cert.get("subject_alt_names", [])
        if not isinstance(sans, list):
            sans = []

        issuer_org = raw_cert.get("issuer_org")
        issuer_cn = raw_cert.get("issuer_cn")
        not_before_raw = raw_cert.get("not_before")
        not_after_raw = raw_cert.get("not_after")
        is_self_signed = raw_cert.get("is_self_signed")
        sni_hostname = raw_cert.get("sni_hostname")
        validation_status = raw_cert.get("validation_status")

        indicators: list[str] = []
        reasons: list[str] = []
        legitimate_causes: list[str] = []

        # Check for empty/incomplete telemetry
        has_substantive_data = any([
            subject_cn, sans, issuer_org, not_before_raw, not_after_raw, is_self_signed is not None, validation_status
        ])
        if not has_substantive_data:
            return asdict(
                TLSAnalysisResult(
                    is_anomaly=False,
                    indicators=["INCOMPLETE_CERTIFICATE_TELEMETRY"],
                    confidence="none",
                    explanation="Certificate telemetry is present but contains no verifiable identity or validity attributes.",
                    legitimate_causes=[
                        "Sensor recorded TLS handshake initiation but certificate payload was dropped or encrypted."
                    ],
                    details={"raw_telemetry": raw_cert, "observed_target_host": target_host},
                )
            )

        # 3. Hostname Matching (CN and SAN)
        if target_host:
            all_cert_names = []
            if subject_cn and isinstance(subject_cn, str):
                all_cert_names.append(subject_cn)
            all_cert_names.extend([s for s in sans if isinstance(s, str)])

            if all_cert_names:
                matches_target = any(match_hostname(target_host, pat) for pat in all_cert_names)
                if not matches_target:
                    indicators.append("CERT_HOSTNAME_MISMATCH")
                    reasons.append(
                        f"presented certificate names ({', '.join(all_cert_names[:3])}) do not match observed host '{target_host}'"
                    )
                    legitimate_causes.append(
                        "Split-horizon DNS routing, multi-tenant CDN domain aggregation, or internal reverse-proxy mapping."
                    )

        # 4. Check against expected trusted IdP hosts (if configured)
        # Keeps certificate hostname matching separate from determining if host is an authorized IdP
        if target_host and self.expected_trusted_hosts:
            is_trusted = any(match_hostname(target_host, trusted) for trusted in self.expected_trusted_hosts)
            if not is_trusted:
                indicators.append("UNTRUSTED_AUTH_HOST")
                reasons.append(
                    f"observed authentication host '{target_host}' is not in configured trusted identity providers"
                )
                legitimate_causes.append(
                    "Federated partner domain, non-standard enterprise IdP tenant, or regional authentication proxy."
                )

        # 5. SNI vs Target Host Consistency
        if sni_hostname and target_host:
            if not match_hostname(target_host, sni_hostname):
                indicators.append("SNI_HOST_MISMATCH")
                reasons.append(
                    f"client SNI header '{sni_hostname}' diverges from target host '{target_host}'"
                )
                legitimate_causes.append(
                    "Fronting proxy, CDN routing endpoint, or domain fronting configuration."
                )

        # 6. Temporal Validity Checks
        not_before = parse_timestamp(not_before_raw)
        not_after = parse_timestamp(not_after_raw)

        if not_before_raw is not None and not_before is None:
            indicators.append("MALFORMED_CERTIFICATE_DATE")
            reasons.append(f"unparseable 'not_before' timestamp: '{not_before_raw}'")

        if not_after_raw is not None and not_after is None:
            indicators.append("MALFORMED_CERTIFICATE_DATE")
            reasons.append(f"unparseable 'not_after' timestamp: '{not_after_raw}'")

        if not_after is not None and reference_time > not_after:
            indicators.append("CERT_EXPIRED")
            reasons.append(f"certificate expired at {not_after.isoformat()} (reference time: {reference_time.isoformat()})")
            legitimate_causes.append(
                "Unmanaged server certificate renewal failure or client system clock skew."
            )

        if not_before is not None and reference_time < not_before:
            indicators.append("CERT_NOT_YET_VALID")
            reasons.append(f"certificate is not valid until {not_before.isoformat()} (reference time: {reference_time.isoformat()})")
            legitimate_causes.append("Client system clock set to a past time or pre-provisioned certificate.")

        # 7. Issuer & Trust Hierarchy Checks
        if is_self_signed is True or validation_status == "untrusted_root":
            indicators.append("UNTRUSTED_SELF_SIGNED_CERT")
            reasons.append("certificate is self-signed or chains to an untrusted root")
            legitimate_causes.append(
                "Corporate SSL/TLS inspection middlebox (Zscaler, BlueCoat, Palo Alto Networks) re-signing traffic with internal enterprise CA; or internal development/lab PKI."
            )

        # 8. Issuer name keyword heuristic:
        # Note: 'proxy' is explicitly excluded because enterprise forward proxies legitimately use it.
        # This is a low-confidence investigative flag and is NOT treated as a standalone attack proof.
        if issuer_org and isinstance(issuer_org, str):
            lowered_org = issuer_org.lower()
            if any(term in lowered_org for term in ("untrusted", "evil", "phish", "attacker", "mitm")):
                indicators.append("SUSPICIOUS_ISSUER_KEYWORD")
                reasons.append(
                    f"issuer organization name '{issuer_org}' matches lab anomaly keyword heuristic (investigative context only)"
                )

        # 9. Determine Overall Actionable Anomaly Status
        # Standalone issuer keyword match or malformed date does NOT trigger is_anomaly alone
        actionable_anomalies = {
            "CERT_HOSTNAME_MISMATCH",
            "SNI_HOST_MISMATCH",
            "CERT_EXPIRED",
            "CERT_NOT_YET_VALID",
            "UNTRUSTED_SELF_SIGNED_CERT",
            "UNTRUSTED_AUTH_HOST",
        }
        has_anomaly = bool(actionable_anomalies.intersection(indicators))

        if not has_anomaly and not indicators:
            indicators.append("NORMAL_CERTIFICATE_OBSERVED")
            explanation = "Certificate observation is valid, unexpired, and matches requested target hostname."
            confidence = "high"
        else:
            explanation = "; ".join(reasons) if reasons else "No anomalous certificate telemetry detected."
            if "CERT_HOSTNAME_MISMATCH" in indicators and "UNTRUSTED_SELF_SIGNED_CERT" in indicators:
                confidence = "high"
            elif has_anomaly:
                confidence = "medium"
            else:
                confidence = "low"

        return asdict(
            TLSAnalysisResult(
                is_anomaly=has_anomaly,
                indicators=indicators,
                confidence=confidence,
                explanation=explanation,
                legitimate_causes=legitimate_causes,
                details={
                    "target_host": target_host,
                    "subject_cn": subject_cn,
                    "sans": sans,
                    "issuer_org": issuer_org,
                    "is_self_signed": is_self_signed,
                    "validation_status": validation_status,
                },
            )
        )
