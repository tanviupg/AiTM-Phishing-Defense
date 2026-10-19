from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class DetectionResult:
    session_id: str
    verdict: str
    risk_score: float  # Uncalibrated heuristic score between 0.0 and 1.0
    triggered_rules: list[str]
    explanation: str


@dataclass
class CompositeDetectionResult:
    """
    Structured result from the opt-in multi-signal composite detection engine.
    Combines redirect analysis, session correlation, and TLS telemetry.

    Indicators are namespaced by source subsystem ('base:RULE', 'tls:INDICATOR', 'session:INDICATOR')
    to prevent ambiguity (e.g. distinguishing session context gaps from certificate observation gaps).

    Note: composite_risk_score is an uncalibrated heuristic composite score [0.0, 1.0],
    not a calibrated statistical probability.
    """
    session_id: str
    base_detection: dict[str, Any]
    session_correlation: Optional[dict[str, Any]]
    tls_analysis: Optional[dict[str, Any]]
    composite_verdict: str
    composite_risk_score: float
    all_triggered_indicators: list[str]  # Namespaced indicators (e.g. 'base:...', 'tls:...', 'session:...')
    composite_explanation: str
    indicators_by_source: dict[str, list[str]] = field(default_factory=dict)


class AiTMDetector:
    """
    Explainable detector for Adversary-in-the-Middle (AiTM) phishing authentication events.

    Focuses on redirect-path anomaly detection and client-observable signals (TLS anomalies).
    Does NOT use ground-truth labels ('scenario') or pre-filled 'replay_indicator'.

    Note: 'risk_score' is an uncalibrated heuristic composite score (0.0 to 1.0),
    not a calibrated statistical probability.
    """

    def analyze_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Analyze an authentication event and return a structured DetectionResult dict.

        Evaluates:
        1. Multi-party intermediate proxy injection / cyclic redirect anomalies.
        2. High redirect volume and domain transition complexity.
        3. Telemetry divergence between reported redirect_count and redirect_chain length.
        4. Client-reported TLS anomalies.
        """
        self._validate_event(event)

        session_id = event["session_id"]
        chain = event["redirect_chain"]
        redirect_count = event["redirect_count"]
        tls_anomaly = event["tls_anomaly"]

        heuristic_score = 0.0
        rules: list[str] = []
        reasons: list[str] = []

        distinct_hosts = set(chain)
        distinct_count = len(distinct_hosts)
        chain_len = len(chain)

        # Feature 1: Redirect Sequence & Transition Graph Analysis
        # Distinguish legitimate federated SSO ([SP, IdP, SP]) from AiTM proxy insertion.
        is_legitimate_sso_pattern = (
            chain_len == 3
            and distinct_count == 2
            and chain[0] == chain[-1]
            and chain[0] != chain[1]
        )

        has_repeated_host = chain_len != distinct_count

        if has_repeated_host and not is_legitimate_sso_pattern:
            if distinct_count >= 3:
                # Intermediary proxy pattern: e.g. [login, proxy, idp, login]
                heuristic_score += 0.35
                rules.append("SUSPICIOUS_REDIRECT_CYCLE")
                reasons.append(
                    f"cyclic redirect loop detected with {distinct_count} distinct intermediary hosts"
                )
            else:
                # Generic host repetition (e.g. redirect loop between 2 hosts > 3 hops)
                heuristic_score += 0.25
                rules.append("REPEATED_REDIRECT_HOST")
                reasons.append("repeated host encountered in redirect sequence")

        # Feature 2: High Transition Complexity (too many distinct organizational entities)
        if distinct_count >= 3 and not ("SUSPICIOUS_REDIRECT_CYCLE" in rules):
            heuristic_score += 0.20
            rules.append("HIGH_TRANSITION_COMPLEXITY")
            reasons.append(
                f"unusually high number of distinct hosts ({distinct_count}) traversed during authentication"
            )

        # Feature 3: High Redirect Count
        if redirect_count > 3:
            heuristic_score += 0.30
            rules.append("EXCESSIVE_REDIRECT_COUNT")
            reasons.append(f"redirect count ({redirect_count}) exceeds standard authentication threshold (>3)")
        elif redirect_count == 3 and not is_legitimate_sso_pattern:
            heuristic_score += 0.15
            rules.append("ELEVATED_REDIRECT_COUNT")
            reasons.append(f"elevated redirect count ({redirect_count}) outside canonical SSO pattern")

        # Feature 4: Telemetry Divergence (redirect_count inconsistent with observed chain)
        if chain_len > 0 and redirect_count < chain_len - 1:
            heuristic_score += 0.15
            rules.append("REDIRECT_TELEMETRY_DIVERGENCE")
            reasons.append(
                f"redirect_count ({redirect_count}) is inconsistent with observed chain length ({chain_len})"
            )

        # Feature 5: TLS Anomaly reported by client/sensor
        if tls_anomaly:
            heuristic_score += 0.25
            rules.append("TLS_ANOMALY")
            reasons.append("event source reported a TLS anomaly")

        # Cap heuristic score at 1.0
        final_score = min(heuristic_score, 1.0)

        # Classification decision based on heuristic risk threshold (0.50)
        verdict = "suspicious" if final_score >= 0.50 else "benign"

        explanation = (
            "; ".join(reasons)
            if reasons
            else "no suspicious redirect or transport patterns detected"
        )

        return asdict(
            DetectionResult(
                session_id=session_id,
                verdict=verdict,
                risk_score=round(final_score, 2),
                triggered_rules=rules,
                explanation=explanation,
            )
        )

    def analyze_event_composite(
        self,
        event: dict[str, Any],
        session_tracker: Optional[Any] = None,
        tls_analyzer: Optional[Any] = None,
        reference_time: Optional[Any] = None,
    ) -> dict[str, Any]:
        """
        Opt-in additive multi-signal evaluation interface.

        Preserves base analyze_event() contract completely, augmenting with:
        - Session context correlation (if session_tracker is provided)
        - Synthetic TLS/certificate telemetry (if tls_analyzer is provided or telemetry present)

        Indicators are namespaced by source:
        - 'base:RULE' for redirect engine rules
        - 'tls:INDICATOR' for transport certificate observations
        - 'session:INDICATOR' for temporal session transitions

        Policy on Isolated Transport & Temporal Signals:
        An isolated CERT_HOSTNAME_MISMATCH (+0.30 modifier) or SUSPICIOUS_CONTEXT_MISMATCH (+0.30 modifier)
        produces an elevated composite score of 0.30. In accordance with defense-in-depth principles,
        this score represents an investigative triage state (flagged for analyst review) rather than
        an automated block, deliberately remaining below the 0.50 automated alert threshold unless
        corroborated by redirect sequence anomalies, untrusted roots, or compound indicators.

        Missing optional components do NOT penalize the event score.
        """
        base_res = self.analyze_event(event)
        session_id = base_res["session_id"]
        composite_score = base_res["risk_score"]
        explanations = [base_res["explanation"]] if base_res["triggered_rules"] else []

        by_source: dict[str, list[str]] = {
            "base": list(base_res["triggered_rules"]),
            "tls": [],
            "session": [],
        }
        all_indicators: list[str] = [f"base:{r}" for r in base_res["triggered_rules"]]

        # 1. Evaluate TLS Telemetry (if analyzer provided or telemetry present)
        tls_res = None
        if tls_analyzer is not None:
            tls_res = tls_analyzer.analyze_event_tls(event, reference_time=reference_time)
        elif "certificate_telemetry" in event:
            try:
                from tls_analyzer import TLSAnalyzer
            except ImportError:
                from module2_detection.tls_analyzer import TLSAnalyzer
            lazy_analyzer = TLSAnalyzer()
            tls_res = lazy_analyzer.analyze_event_tls(event, reference_time=reference_time)

        if tls_res is not None:
            by_source["tls"] = list(tls_res["indicators"])
            for ind in tls_res["indicators"]:
                tag = f"tls:{ind}"
                if tag not in all_indicators:
                    all_indicators.append(tag)

            if tls_res["is_anomaly"]:
                # Additive transparent modifiers
                if "CERT_HOSTNAME_MISMATCH" in tls_res["indicators"] or "UNTRUSTED_AUTH_HOST" in tls_res["indicators"]:
                    composite_score += 0.30
                if "UNTRUSTED_SELF_SIGNED_CERT" in tls_res["indicators"]:
                    composite_score += 0.20
                if "CERT_EXPIRED" in tls_res["indicators"] or "CERT_NOT_YET_VALID" in tls_res["indicators"]:
                    composite_score += 0.15
                if "SNI_HOST_MISMATCH" in tls_res["indicators"]:
                    composite_score += 0.15
                explanations.append(f"TLS: {tls_res['explanation']}")

        # 2. Evaluate Session Context Correlation (if session_tracker provided)
        session_res = None
        if session_tracker is not None:
            session_res = session_tracker.correlate_event(event)
            by_source["session"] = list(session_res["indicators"])
            for ind in session_res["indicators"]:
                tag = f"session:{ind}"
                if tag not in all_indicators:
                    all_indicators.append(tag)

            session_inds = set(session_res["indicators"])

            # Token binding failure (+0.35)
            if "TOKEN_BINDING_FAILURE" in session_inds:
                composite_score += 0.35

            # Replay metadata modifiers
            if "CONCURRENT_SESSION_BIFURCATION" in session_inds:
                composite_score += 0.25
            if "CLIENT_PLATFORM_DIVERGENCE" in session_inds:
                composite_score += 0.25
            if "DATACENTER_SOURCE_TRANSITION" in session_inds:
                composite_score += 0.20

            if session_res["is_correlated"]:
                if "SUSPICIOUS_CONTEXT_MISMATCH" in session_inds:
                    composite_score += 0.30
                elif "DEVICE_CONTEXT_CHANGED" in session_inds:
                    composite_score += 0.15
                elif "RAPID_SOURCE_IP_CHANGE" in session_inds:
                    composite_score += 0.10

            if any(ind in session_inds for ind in (
                "TOKEN_BINDING_FAILURE", "CONCURRENT_SESSION_BIFURCATION",
                "CLIENT_PLATFORM_DIVERGENCE", "DATACENTER_SOURCE_TRANSITION",
                "SUSPICIOUS_CONTEXT_MISMATCH", "DEVICE_CONTEXT_CHANGED", "RAPID_SOURCE_IP_CHANGE"
            )):
                explanations.append(f"Temporal: {session_res['explanation']}")
        elif isinstance(event.get("token_binding_status"), str):
            tb_norm = event["token_binding_status"].strip().lower()
            if tb_norm in ("failed", "key_mismatch"):
                composite_score += 0.35
                tag = "session:TOKEN_BINDING_FAILURE"
                if tag not in all_indicators:
                    all_indicators.append(tag)
                by_source.setdefault("session", []).append("TOKEN_BINDING_FAILURE")
                explanations.append(f"Token Binding: cryptographic token proof-of-possession binding validation failed (status: '{event['token_binding_status']}')")

        final_composite_score = min(round(composite_score, 2), 1.0)
        composite_verdict = "suspicious" if final_composite_score >= 0.50 else "benign"

        composite_explanation = (
            "; ".join(explanations)
            if explanations
            else "no suspicious redirect, transport, or temporal context patterns detected"
        )

        return asdict(
            CompositeDetectionResult(
                session_id=session_id,
                base_detection=base_res,
                session_correlation=session_res,
                tls_analysis=tls_res,
                composite_verdict=composite_verdict,
                composite_risk_score=final_composite_score,
                all_triggered_indicators=all_indicators,
                composite_explanation=composite_explanation,
                indicators_by_source=by_source,
            )
        )

    @staticmethod
    def _validate_event(event: dict[str, Any]) -> None:
        """Enforces schema compliance for required fields and types."""
        required = {
            "session_id",
            "redirect_count",
            "redirect_chain",
            "tls_anomaly",
        }

        if not isinstance(event, dict):
            raise ValueError("event must be a dictionary")

        missing = required - event.keys()
        if missing:
            raise ValueError(
                f"Missing required fields: {', '.join(sorted(missing))}"
            )

        if not isinstance(event["session_id"], str):
            raise ValueError("session_id must be a string")

        count = event["redirect_count"]
        # In Python, bool is a subclass of int, so isinstance(True, int) is True; explicitly exclude bool
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("redirect_count must be a non-negative integer")

        chain = event["redirect_chain"]
        if not isinstance(chain, list) or not all(
            isinstance(host, str) for host in chain
        ):
            raise ValueError("redirect_chain must be a list of strings")

        tls = event["tls_anomaly"]
        if isinstance(tls, bool) is False:
            raise ValueError("tls_anomaly must be a boolean")
